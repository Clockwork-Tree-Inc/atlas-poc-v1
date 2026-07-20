"""Property tests for VERIFIABLE re-sharing (Feldman VSS).

Run from backend/ with sim/reshare on the path:
    PYTHONPATH=.:sim/reshare python sim/reshare/test_reshare_vss.py
Prints PASS/FAIL per property; exits 0 iff ALL pass.

Properties (this module's whole reason to exist is #2 and #3):
  1. Honest re-sharing still works: new committee reconstructs the SAME secret;
     secret is never assembled (combine never called by the protocol).
  2. VERIFIABILITY: every honest sub-share passes the Feldman check.
  3. CHEATER DETECTION + ATTRIBUTION: a malicious dealer sending an inconsistent
     sub-share (or a wrong constant term) is DETECTED and the exact dealer index
     is named in the complaint.
  4. ROBUSTNESS: with n old holders and up to t cheaters excluded, the honest
     majority still completes a correct re-share (as long as >= k_old honest
     dealers remain qualified).
  5. Below-threshold reveals nothing (info-theoretic, over the prime field).
"""

from __future__ import annotations

import sys
from itertools import combinations
from typing import List, Sequence, Tuple

import reshare_vss as rv
from reshare_vss import (
    DealerBroadcast,
    VShare,
    combine,
    feldman_deal,
    lagrange_at_zero,
    reshare_verifiable,
    verify_share,
    Q,
)

# A realistic 256-bit root-of-trust seed, taken as a field element mod Q.
SECRET = int.from_bytes(b"atlas-root-of-trust-32byteseed!!", "big") % Q


class ResultBoard:
    def __init__(self) -> None:
        self.rows: List[Tuple[str, bool, str]] = []

    def record(self, name: str, ok: bool, detail: str = "") -> None:
        self.rows.append((name, ok, detail))
        print(f"[{'PASS' if ok else 'FAIL'}] {name}")
        for line in detail.splitlines():
            if line:
                print(f"         {line}")

    def all_ok(self) -> bool:
        return all(ok for _, ok, _ in self.rows)


def _initial(secret: int, xs: Sequence[int], k: int):
    """Feldman-deal the initial committee; return (shares list, commitments)."""
    shares, commitments, _ = feldman_deal(secret, list(xs), k)
    return [shares[x] for x in xs], commitments


def _interp_at(points: Sequence[Tuple[int, int]], x: int) -> int:
    """Lagrange-evaluate the interpolating polynomial (mod Q) at x."""
    total = 0
    for i, (xi, yi) in enumerate(points):
        num, den = 1, 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            num = (num * (x - xj)) % Q
            den = (den * (xi - xj)) % Q
        total = (total + yi * num * pow(den, -1, Q)) % Q
    return total


# ---------------------------------------------------------------------------
# PROPERTY 1 -- honest re-sharing works; secret never assembled
# ---------------------------------------------------------------------------
def property_1(board: ResultBoard) -> None:
    detail, ok = [], True

    # Spy on combine: the protocol must NEVER assemble the secret.
    calls = {"n": 0}
    real_combine = rv.combine

    def spy(shares):
        calls["n"] += 1
        return real_combine(shares)

    rv.combine = spy
    try:
        # 2-of-3 -> 3-of-5 (change membership AND threshold), all 5 old holders deal.
        old, V = _initial(SECRET, [1, 2, 3], k=2)
        res = reshare_verifiable(
            old, new_indices=[1, 2, 3, 4, 5], k_old=2, k_new=3, orig_commitments=V
        )
    finally:
        rv.combine = real_combine

    no_assemble = calls["n"] == 0
    detail.append(f"combine() called during protocol: {calls['n']} (expected 0)")

    # every k_new-subset of the new committee reconstructs the SAME secret
    rec_ok = all(real_combine(list(c)) == SECRET for c in combinations(res.new_shares, 3))
    detail.append(f"new 3-of-5 committee: all C(5,3) triples reconstruct == {rec_ok}; "
                  f"epoch {old[0].epoch} -> {res.new_shares[0].epoch}")
    detail.append(f"no complaints on honest run: {res.complaints == []}, "
                  f"qualified dealers = {res.qualified}")

    # shares are genuinely fresh (not equal to old at shared indices)
    fresh = any(res.new_shares[i].value != old[i].value for i in range(3))
    detail.append(f"shares refreshed (differ from old): {fresh}")

    ok = no_assemble and rec_ok and fresh and res.complaints == []
    board.record("Property 1: honest re-share works; SAME secret; never assembled",
                 ok, "\n".join(detail))


# ---------------------------------------------------------------------------
# PROPERTY 2 -- verifiability: every honest sub-share passes Feldman
# ---------------------------------------------------------------------------
def property_2(board: ResultBoard) -> None:
    detail, ok = [], True

    old, V = _initial(SECRET, [1, 2, 3, 4], k=3)
    new_indices = [1, 2, 3, 4, 5]

    # (i) initial shares verify against the original commitments V
    init_ok = all(verify_share(s.index, s.value, V) for s in old)
    detail.append(f"all initial shares pass Feldman vs V: {init_ok}")

    # (ii) every honest sub-share of every dealer verifies for every recipient
    checks = 0
    all_sub_ok = True
    for s in old:
        bc, _ = rv.reshare_deal(s.index, s.value, new_indices=new_indices, k_new=3)
        for nx in new_indices:
            good, reason = rv.verify_subshare(
                bc, nx, dealer_old_index=s.index, orig_commitments=V
            )
            checks += 1
            all_sub_ok &= good
    detail.append(f"honest sub-shares verified: {checks} checks, all pass == {all_sub_ok}")
    detail.append("verification is public: g^sub == prod_j C_j^(x^j) mod P, "
                  "plus C_0 binds to G^{s_i} via V")

    ok = init_ok and all_sub_ok
    board.record("Property 2: VERIFIABILITY -- every honest sub-share verifies",
                 ok, "\n".join(detail))


# ---------------------------------------------------------------------------
# PROPERTY 3 -- cheater DETECTION + ATTRIBUTION
# ---------------------------------------------------------------------------
def property_3(board: ResultBoard) -> None:
    detail, ok = [], True
    old, V = _initial(SECRET, [1, 2, 3], k=2)
    new_indices = [1, 2, 3, 4]

    # --- Attack A: dealer 2 sends an INCONSISTENT sub-share (off the poly) ---
    honest_bc, _ = rv.reshare_deal(2, old[1].value, new_indices=new_indices, k_new=2)
    bad_subs = dict(honest_bc.subshares)
    bad_subs[3] = (bad_subs[3] + 12345) % Q          # corrupt sub-share to party 3
    cheat_bc = DealerBroadcast(2, honest_bc.commitments, bad_subs)

    resA = reshare_verifiable(
        old, new_indices=new_indices, k_old=2, k_new=2,
        orig_commitments=V, tamper={2: cheat_bc},
    )
    namedA = {c.accused_dealer_index for c in resA.complaints}
    detectedA = 2 in resA.disqualified and namedA == {2}
    # the honest recipient (party 3) is exactly the accuser
    accuserA = any(c.accuser_new_index == 3 and c.accused_dealer_index == 2
                   for c in resA.complaints)
    detail.append(f"[A inconsistent sub-share] disqualified={resA.disqualified}, "
                  f"complaints name only dealer 2 == {namedA == {2}}, "
                  f"accuser is party 3 == {accuserA}")
    detail.append(f"    reason: {resA.complaints[0].reason}")
    # honest dealers {1,3} still >= k_old=2, so re-share still completes correctly
    stillA = all(combine(list(c)) == SECRET
                 for c in combinations(resA.new_shares, 2))
    detail.append(f"    honest dealers {resA.qualified} still reconstruct SAME secret: {stillA}")

    # --- Attack B: dealer 2 re-shares a WRONG constant term (subtle) --------
    # Internally consistent sub-shares, but Q_2(0) != s_2 -> binding check fails.
    wrong_shares, wrong_C, _ = feldman_deal((old[1].value + 999) % Q, new_indices, 2)
    forge_bc = DealerBroadcast(2, wrong_C, {x: sh.value for x, sh in wrong_shares.items()})
    resB = reshare_verifiable(
        old, new_indices=new_indices, k_old=2, k_new=2,
        orig_commitments=V, tamper={2: forge_bc},
    )
    namedB = {c.accused_dealer_index for c in resB.complaints}
    # sub-shares are self-consistent (pass check A) but fail the binding check B
    selfconsistent = all(
        verify_share(nx, forge_bc.subshares[nx], forge_bc.commitments) for nx in new_indices
    )
    detectedB = 2 in resB.disqualified and namedB == {2}
    detail.append(f"[B wrong constant term] sub-shares self-consistent (pass check A) == "
                  f"{selfconsistent}; still detected & named dealer 2 == {detectedB}")
    detail.append(f"    reason: {resB.complaints[0].reason}")

    ok = detectedA and accuserA and stillA and detectedB and selfconsistent
    board.record("Property 3: CHEATER DETECTION + ATTRIBUTION (right dealer named)",
                 ok, "\n".join(detail))


# ---------------------------------------------------------------------------
# PROPERTY 4 -- robustness with up to t cheaters excluded
# ---------------------------------------------------------------------------
def property_4(board: ResultBoard) -> None:
    detail, ok = [], True
    # n=5 old holders participate, old threshold k_old=3. Inject t=2 cheaters.
    old, V = _initial(SECRET, [1, 2, 3, 4, 5], k=3)
    new_indices = [1, 2, 3, 4, 5, 6]

    tamper = {}
    for cheat in (2, 4):  # dealers 2 and 4 each send one bad sub-share
        bc, _ = rv.reshare_deal(cheat, old[cheat - 1].value,
                                new_indices=new_indices, k_new=3)
        subs = dict(bc.subshares)
        subs[1] = (subs[1] + 777) % Q
        tamper[cheat] = DealerBroadcast(cheat, bc.commitments, subs)

    res = reshare_verifiable(
        old, new_indices=new_indices, k_old=3, k_new=3,
        orig_commitments=V, tamper=tamper,
    )
    excluded_ok = res.disqualified == [2, 4]
    honest_left = res.qualified  # {1,3,5}
    enough = len(honest_left) >= 3
    detail.append(f"injected cheaters {{2,4}}; disqualified={res.disqualified}; "
                  f"qualified honest dealers={honest_left} (>= k_old=3: {enough})")

    # despite 2 excluded dealers, the new committee correctly re-shares the secret
    rec = all(combine(list(c)) == SECRET for c in combinations(res.new_shares, 3))
    detail.append(f"new 3-of-6 committee: all C(6,3) triples reconstruct SAME secret == {rec}")

    # negative control: if too many cheat (only 2 honest < k_old=3), we REFUSE.
    tamper2 = {}
    for cheat in (2, 4, 5):
        bc, _ = rv.reshare_deal(cheat, old[cheat - 1].value,
                                new_indices=new_indices, k_new=3)
        subs = dict(bc.subshares)
        subs[1] = (subs[1] + 5) % Q
        tamper2[cheat] = DealerBroadcast(cheat, bc.commitments, subs)
    refused = False
    try:
        reshare_verifiable(old, new_indices=new_indices, k_old=3, k_new=3,
                           orig_commitments=V, tamper=tamper2)
    except ValueError as e:
        refused = "honest dealers left" in str(e)
    detail.append(f"3 cheaters -> only 2 honest < k_old=3: protocol REFUSES (no silent "
                  f"corruption): {refused}")

    ok = excluded_ok and enough and rec and refused
    board.record("Property 4: ROBUSTNESS -- honest majority completes despite t cheaters",
                 ok, "\n".join(detail))


# ---------------------------------------------------------------------------
# PROPERTY 5 -- below-threshold reveals nothing (info-theoretic, prime field)
# ---------------------------------------------------------------------------
def property_5(board: ResultBoard) -> None:
    detail, ok = [], True
    # honest re-share to a 3-of-5 committee, then inspect its shares
    old, V = _initial(SECRET, [1, 2, 3], k=2)
    res = reshare_verifiable(old, new_indices=[1, 2, 3, 4, 5], k_old=2, k_new=3,
                             orig_commitments=V)
    new = res.new_shares
    k = 3

    # Take k-1 = 2 shares. Over a prime field, for ANY candidate secret s* there
    # is EXACTLY ONE degree-(k-1) polynomial through those 2 points and (0, s*):
    # so every s* is equally consistent -> the 2 shares reveal ZERO information.
    known = [(new[0].index, new[0].value), (new[1].index, new[1].value)]
    x0 = new[2].index  # a fresh "missing" coordinate

    # For random candidate secrets, solve the missing share y0 s.t. secret == s*,
    # then confirm reconstruction yields exactly s* -> every secret is reachable.
    candidates = [SECRET, (SECRET + 1) % Q, 0, 1, Q - 1] + [rv._rand_field() for _ in range(200)]
    reached, ys = 0, set()
    for s_star in candidates:
        # unique poly through known + (0, s*); its value at x0 is the needed share
        y0 = _interp_at(known + [(0, s_star)], x0)
        pts = known + [(x0, y0)]
        rec = combine([VShare(px, py) for px, py in pts])
        if rec == s_star:
            reached += 1
        ys.add(y0)
    all_reached = reached == len(candidates)
    injective = len(ys) == len(candidates)  # distinct secrets -> distinct missing share
    detail.append(f"below threshold (2 of 3): {reached}/{len(candidates)} candidate secrets "
                  f"reachable == {all_reached} (every secret equally consistent -> 0 info)")
    detail.append(f"secret<->missing-share map is injective: {injective}")

    # at threshold: 3 shares determine the secret UNIQUELY, and it's the true one
    at = combine(new[:3])
    detail.append(f"at threshold (3 of 3): reconstructs unique secret == true SECRET: "
                  f"{at == SECRET}")

    ok = all_reached and injective and (at == SECRET)
    board.record("Property 5: below-threshold reveals nothing (info-theoretic)",
                 ok, "\n".join(detail))


def main() -> int:
    print("=" * 72)
    print("Atlas PoC -- VERIFIABLE re-sharing (Feldman VSS) reference sim")
    print(f"group: 256-bit safe prime P, order Q=(P-1)/2, generator G={rv.G}")
    print("=" * 72)
    board = ResultBoard()
    property_1(board)
    property_2(board)
    property_3(board)
    property_4(board)
    property_5(board)
    print("-" * 72)
    passed = sum(1 for _, ok, _ in board.rows if ok)
    print(f"SUMMARY: {passed}/{len(board.rows)} properties PASS")
    print("=" * 72)
    return 0 if board.all_ok() else 1


if __name__ == "__main__":
    sys.exit(main())
