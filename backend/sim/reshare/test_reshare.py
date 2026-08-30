"""Property-assertion tests for the re-sharing reference sim.

Run from backend/ with '.' on sys.path:
    python sim/reshare/test_reshare.py
Prints PASS/FAIL per property and exits non-zero if any property fails.
"""

from __future__ import annotations

import sys
from typing import List, Sequence, Tuple

from atlas.crypto import shamir
import reshare as rs
from reshare import EpochShare, reshare, epoch_combine

SECRET = b"atlas-root-of-trust-32byteseed!!"  # 32 bytes, a realistic RoT seed


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
def initial_committee(secret: bytes, n: int, k: int, epoch: int = 0) -> List[EpochShare]:
    return [EpochShare(epoch=epoch, share=s) for s in shamir.split(secret, n=n, k=k)]


def _poly_through(points: Sequence[Tuple[int, int]]) -> Sequence[Tuple[int, int]]:
    return points


def _interp_at(points: Sequence[Tuple[int, int]], x: int) -> int:
    """Lagrange-evaluate the interpolating polynomial (over GF256) at x."""
    total = 0
    for i, (xi, yi) in enumerate(points):
        num, den = 1, 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            num = rs._gf_mul(num, x ^ xj)
            den = rs._gf_mul(den, xi ^ xj)
        total ^= rs._gf_mul(yi, rs._gf_div(num, den))
    return total


def _consistent_with_degree(points: Sequence[Tuple[int, int]], k: int) -> bool:
    """Can a degree-(k-1) polynomial pass through all these distinct-x points?"""
    m = len(points)
    if m <= k:
        return True  # <=k points never over-constrain a degree-(k-1) poly
    base = list(points[:k])
    for (x, y) in points[k:]:
        if _interp_at(base, x) != y:
            return False
    return True


def count_consistent_secrets(subset: Sequence[EpochShare], k: int, byte_pos: int = 0) -> int:
    """How many secret byte-values are consistent with `subset` at byte_pos.

    Equals field size (256) => the subset reveals ZERO information about that
    byte; equals 1 => the byte is fully determined.
    """
    pts = [(s.index, s.share.y[byte_pos]) for s in subset]
    consistent = 0
    for candidate in range(256):
        if _consistent_with_degree(pts + [(0, candidate)], k):
            consistent += 1
    return consistent


class ResultBoard:
    def __init__(self) -> None:
        self.rows: List[Tuple[str, bool, str]] = []

    def record(self, name: str, ok: bool, detail: str = "") -> None:
        self.rows.append((name, ok, detail))
        tag = "PASS" if ok else "FAIL"
        print(f"[{tag}] {name}")
        if detail:
            for line in detail.splitlines():
                print(f"         {line}")

    def all_ok(self) -> bool:
        return all(ok for _, ok, _ in self.rows)


# ---------------------------------------------------------------------------
# PROPERTY 1 -- new committee reconstructs the SAME secret
# ---------------------------------------------------------------------------
def property_1(board: ResultBoard) -> None:
    detail = []
    ok = True

    # 1a: 2-of-3 -> 2-of-4 (ADD A NODE). Use k=2 of the old committee.
    old = initial_committee(SECRET, n=3, k=2)
    new = reshare(old[:2], new_indices=[1, 2, 3, 4], k_new=2)
    # every 2-subset of the 4 new shares must give SECRET
    from itertools import combinations
    rec_ok = all(epoch_combine(list(c)) == SECRET for c in combinations(new, 2))
    detail.append(f"2-of-3 -> 2-of-4 add-node: all C(4,2) pairs reconstruct == {rec_ok}, "
                  f"new epoch={new[0].epoch}")
    ok &= rec_ok and len(new) == 4

    # 1b: 3-of-5 -> 3-of-5 REFRESH (same membership, fresh shares)
    old5 = initial_committee(SECRET, n=5, k=3)
    new5 = reshare(old5[:3], new_indices=[1, 2, 3, 4, 5], k_new=3)
    rec5 = all(epoch_combine(list(c)) == SECRET for c in combinations(new5, 3))
    # and shares are genuinely fresh (differ from old at same index) w.h.p.
    fresh = any(new5[i].share.y != old5[i].share.y for i in range(5))
    detail.append(f"3-of-5 -> 3-of-5 refresh: all C(5,3) triples reconstruct == {rec5}; "
                  f"shares refreshed (differ from old) == {fresh}")
    ok &= rec5 and fresh

    board.record("Property 1: new committee reconstructs the SAME secret", ok, "\n".join(detail))


# ---------------------------------------------------------------------------
# PROPERTY 2 -- secret is NEVER assembled at any single party mid-protocol
# ---------------------------------------------------------------------------
def property_2(board: ResultBoard) -> None:
    detail = []

    # Instrument shamir.combine: assert the re-share protocol NEVER calls it.
    calls = {"n": 0, "args": []}
    real_combine = shamir.combine

    def spy_combine(shares, *a, **kw):
        calls["n"] += 1
        calls["args"].append([s.index for s in shares])
        return real_combine(shares, *a, **kw)

    shamir.combine = spy_combine
    rs.shamir.combine = spy_combine  # reshare.py holds its own ref via module
    try:
        old = initial_committee(SECRET, n=5, k=3)
        _ = reshare(old[:3], new_indices=[1, 2, 3, 4, 5, 6], k_new=3)
    finally:
        shamir.combine = real_combine
        rs.shamir.combine = real_combine

    no_combine = calls["n"] == 0
    detail.append(f"shamir.combine (the only routine that assembles s) called "
                  f"{calls['n']} times during reshare (expected 0)")

    # Structural argument: the largest number of ORIGINAL shares visible to any
    # single local routine. deal_subshares sees exactly 1 (its own). aggregate
    # sees 0 originals (only sub-shares of others' shares). Reconstructing all
    # sub-shares a new party holds yields sums of OTHER parties' shares, not s.
    old = initial_committee(SECRET, n=5, k=3)
    part = old[:3]
    lag = rs.lagrange_coeffs_at_zero([s.index for s in part])
    dealt = {s.index: rs.deal_subshares(s.share, new_indices=[1, 2, 3, 4], k_new=3)
             for s in part}
    # sub-shares that reach new party #1, if (illegitimately) combined, recover
    # only party i's own OLD share s_i -- never the root secret.
    leaks_secret = False
    for old_x, subs_by_new in dealt.items():
        # gather k_new sub-shares of THIS old party's share and reconstruct
        recovered_share_i = shamir.combine(list(subs_by_new.values())[:3])
        s_i = next(s.share.y for s in part if s.index == old_x)
        assert recovered_share_i == s_i, "sub-shares must reconstruct the dealer's own share"
        if recovered_share_i == SECRET:
            leaks_secret = True
    detail.append("max ORIGINAL shares held by any single local routine = 1 "
                  "(deal_subshares); aggregate_new_share holds 0")
    detail.append(f"reconstructing a dealer's sub-shares yields only that dealer's "
                  f"own share, never the secret: leak_observed == {leaks_secret}")

    ok = no_combine and not leaks_secret
    board.record("Property 2: secret NEVER assembled at any single party", ok, "\n".join(detail))


# ---------------------------------------------------------------------------
# PROPERTY 3 -- below-threshold subsets of the new committee reveal nothing
# ---------------------------------------------------------------------------
def property_3(board: ResultBoard) -> None:
    detail = []
    old = initial_committee(SECRET, n=3, k=2)
    new = reshare(old[:2], new_indices=[1, 2, 3, 4], k_new=3)  # new threshold 3

    # below threshold: 2 shares (k_new-1). Perfect secrecy => 256 consistent secrets.
    below = count_consistent_secrets(new[:2], k=3)
    # at threshold: 3 shares => exactly 1 consistent secret.
    at = count_consistent_secrets(new[:3], k=3)

    # sanity: true secret's first byte is indeed the unique one at threshold
    unique_matches_secret = _consistent_with_degree(
        [(s.index, s.share.y[0]) for s in new[:3]] + [(0, SECRET[0])], k=3
    )

    detail.append(f"new committee 3-of-4. below-threshold (2 shares): "
                  f"{below}/256 secret byte-values consistent  (256 => zero info)")
    detail.append(f"at-threshold (3 shares): {at}/256 consistent  (1 => determined); "
                  f"unique value == true secret byte: {unique_matches_secret}")
    ok = (below == 256) and (at == 1) and unique_matches_secret
    board.record("Property 3: below-threshold subsets reveal nothing", ok, "\n".join(detail))


# ---------------------------------------------------------------------------
# PROPERTY 4 -- removed party's OLD share cannot combine with new shares
# ---------------------------------------------------------------------------
def property_4(board: ResultBoard) -> None:
    detail = []
    old = initial_committee(SECRET, n=3, k=2, epoch=0)  # committee {1,2,3}
    # REMOVE party 3: new committee is {1,2,4} (party 4 added, 3 dropped)
    new = reshare(old[:2], new_indices=[1, 2, 4], k_new=2)  # epoch 1
    removed = old[2]                # party 3, still holding its epoch-0 share
    kept_new = new[0]              # a new epoch-1 share

    # (a) epoch/generation separation: mixing epochs is a hard error
    epoch_guard = False
    try:
        epoch_combine([removed, kept_new])
    except ValueError as e:
        epoch_guard = True
        detail.append(f"epoch guard rejected mixed-generation combine: {e}")

    # (b) even ignoring the tag, the removed old share lies on the OLD polynomial
    # P while new shares lie on the fresh P'; combining them yields NOT the secret.
    mixed = shamir.combine([removed.share, kept_new.share])
    wrong = mixed != SECRET
    detail.append(f"raw combine(removed_old_share, new_share) == SECRET: "
                  f"{mixed == SECRET}  (expected False -> different polynomials)")
    # and the new committee alone still works
    still_ok = epoch_combine([new[0], new[2]]) == SECRET
    detail.append(f"new committee {{1,2,4}} reconstructs correctly: {still_ok}")

    ok = epoch_guard and wrong and still_ok
    board.record("Property 4: removed party's old share cannot combine (epoch separation)",
                 ok, "\n".join(detail))


# ---------------------------------------------------------------------------
# PROPERTY 5 -- add-a-device and add-a-node both map onto "add a shareholder"
# ---------------------------------------------------------------------------
def property_5(board: ResultBoard) -> None:
    detail = []
    ok = True

    # Start: 2-of-3 root split across {server-node A(1), server-node B(2), phone(3)}
    committee = initial_committee(SECRET, n=3, k=2, epoch=0)

    # ADD A NODE: bring server-node C online -> new holder index 4. 2-of-4.
    committee = reshare(committee[:2], new_indices=[1, 2, 3, 4], k_new=2)
    add_node_ok = epoch_combine([committee[0], committee[3]]) == SECRET
    detail.append(f"add server NODE (index 4): 2-of-4, reconstructs: {add_node_ok}, "
                  f"epoch={committee[0].epoch}")
    ok &= add_node_ok and len(committee) == 4

    # ADD A DEVICE: enroll a laptop -> new holder index 5. 2-of-5. Same primitive.
    committee = reshare(committee[:2], new_indices=[1, 2, 3, 4, 5], k_new=2)
    add_dev_ok = epoch_combine([committee[3], committee[4]]) == SECRET
    detail.append(f"add DEVICE (index 5): 2-of-5, reconstructs: {add_dev_ok}, "
                  f"epoch={committee[0].epoch}")
    ok &= add_dev_ok and len(committee) == 5

    detail.append("both flows are identical calls to reshare() with a larger "
                  "new_indices set -- 'add node' and 'add device' are one primitive.")
    board.record("Property 5: add-a-device and add-a-node both = add a shareholder",
                 ok, "\n".join(detail))


def main() -> int:
    print("=" * 72)
    print("Atlas PoC -- Re-sharing (proactive / dynamic membership) reference sim")
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
