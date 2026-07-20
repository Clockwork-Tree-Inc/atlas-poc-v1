"""VERIFIABLE re-sharing (Feldman VSS) for Atlas proactive secret sharing.

PURE-PYTHON REFERENCE ONLY -- NOT production crypto. This module closes the
one gap left open by ``reshare.py``: that sim assumes HONEST dealers, so a
malicious/buggy old share-holder can hand *inconsistent* sub-shares and
silently corrupt a new committee member's share with NO way to detect or blame
it. Here every sub-share is publicly VERIFIABLE against the dealer's committed
polynomial, so a cheating dealer is DETECTED and ATTRIBUTED (named) before its
contribution is ever aggregated.

WHY A PRIME FIELD (not the GF(256) core in atlas.crypto.shamir)
---------------------------------------------------------------
Feldman commitments need a group where the discrete log is hard: the dealer
publishes C_j = g^{a_j}, and a recipient checks g^{share} == prod_j C_j^{x^j}
WITHOUT learning the a_j. That requires a large prime-order group, which GF(256)
is not. So this module implements its own small Shamir over Z_Q (Q a 256-bit
prime = the order of a modular-exponentiation group), independent of the
GF(256) code, which is left untouched.

GROUP / PARAMETERS  (documented, and re-verified at import time)
---------------------------------------------------------------
We use a modular-exponentiation group (a reference-sim choice explicitly
allowed for a PoC; a real deployment would use secp256k1 or a standard MODP
group). We pick a 256-bit SAFE PRIME  P = 2*Q + 1  with Q also prime, and the
generator  G = 4 = 2^2  which is a quadratic residue and therefore generates
the unique prime-order-Q subgroup (the QRs mod P). Secrets, polynomial
coefficients and shares live in Z_Q (exponent field); commitments live in the
order-Q subgroup of Z_P^*.

    P = 2*Q + 1        (safe prime, 256-bit)
    Q = (P-1)//2       (prime, = group order)
    G = 4              (generator of the order-Q subgroup)

Both P and Q are checked prime with Miller-Rabin when this module is imported,
and G is checked to have order Q, so the parameters are self-certifying.

THE SCHEME
----------
Feldman-VSS deal of secret s (degree k-1 poly A(x)=a0+..+a_{k-1}x^{k-1}, a0=s):
    * commitments  V_j = G^{a_j} mod P           (public)
    * share of party x is  s_x = A(x) mod Q       (private, sent to x)
    * anyone verifies:  G^{s_x} == prod_j V_j^{x^j}  (mod P)

Verifiable RE-SHARING (old committee -> new committee) with the SAME secret:
    1. Each old holder i (share s_i) acts as a Feldman DEALER: it picks a fresh
       degree (k_new-1) poly Q_i with Q_i(0)=s_i, BROADCASTS commitments
       C_{i,j}=G^{Q_i coeff j}, and sends sub-share Q_i(x'_l) to each new party l.
    2. Each new party l VERIFIES every sub-share it receives against that
       dealer's commitments  ( G^{sub} == prod_j C_{i,j}^{(x'_l)^j} ).  A bad
       sub-share fails this check -> party l files a COMPLAINT naming dealer i.
    3. Each new party ALSO checks the dealer's committed constant term binds to
       the dealer's TRUE old share:  C_{i,0} == prod_j V_j^{x_i^j}  (mod P),
       using the ORIGINAL secret's commitments V. This stops a subtler cheat:
       a dealer that re-shares a WRONG constant term (internally consistent
       sub-shares, but not of its real s_i) is caught and named too.
    4. Any dealer with a complaint is DISQUALIFIED. New shares are aggregated
       ONLY from the qualified dealers, Lagrange-weighted over that set. As long
       as >= k_old honest dealers remain qualified, the new committee holds a
       correct re-share of the SAME secret.

Like reshare.py, the secret is NEVER assembled: no party holds >= k_old shares,
and ``combine`` (the only routine that reconstructs s) is never called by the
protocol -- only by tests, to check the result.

HONEST LIMITS (see report): the "broadcast" and "send sub-share to party l" are
modelled as in-process data passing. A real deployment still needs
authenticated/encrypted channels (Atlas has kem/sign/AEAD for this), a
liveness-bounded complaint round, and agreement on the qualified-dealer set
(a broadcast/BFT layer) so all honest parties disqualify the same cheaters.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from atlas.crypto import primitives  # reuse atlas CSPRNG; atlas code unchanged

# ---------------------------------------------------------------------------
# Group parameters (256-bit safe prime; self-verified below)
# ---------------------------------------------------------------------------
P = 0x93382F2DC5868E3795C13E11D3A72EDD78BB30E157AE3ADBF7421A786AEDD23F
Q = (P - 1) // 2  # group order (prime)
G = 4             # 2^2, generator of the order-Q subgroup (quadratic residues)


def _miller_rabin(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for p in small:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = 2 + _rand_below(n - 3)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _rand_below(bound: int) -> int:
    """Uniform int in [0, bound) using atlas's CSPRNG (rejection sampling)."""
    if bound <= 0:
        raise ValueError("bound must be positive")
    nbytes = (bound.bit_length() + 7) // 8 + 1
    while True:
        val = int.from_bytes(primitives.random_bytes(nbytes), "big")
        # unbiased: reject the top non-multiple slice
        limit = (1 << (8 * nbytes)) - ((1 << (8 * nbytes)) % bound)
        if val < limit:
            return val % bound


def _rand_field() -> int:
    """Uniform nonzero-friendly element of Z_Q (0..Q-1)."""
    return _rand_below(Q)


def _self_check_params() -> None:
    assert _miller_rabin(P), "P is not prime"
    assert _miller_rabin(Q), "Q=(P-1)//2 is not prime (P not a safe prime)"
    assert P == 2 * Q + 1, "P must equal 2Q+1"
    assert pow(G, Q, P) == 1 and G % P != 1, "G must have order Q"


_self_check_params()


# ---------------------------------------------------------------------------
# Prime-field Shamir over Z_Q
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class VShare:
    """A verifiable share: x-coordinate and field value s = A(x) mod Q."""

    index: int
    value: int
    epoch: int = 0


def _poly_eval(coeffs: Sequence[int], x: int) -> int:
    """Evaluate A(x) = coeffs[0] + coeffs[1] x + ... (mod Q) via Horner."""
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % Q
    return acc


def commit(coeffs: Sequence[int]) -> List[int]:
    """Feldman commitments C_j = G^{coeffs[j]} mod P."""
    return [pow(G, c % Q, P) for c in coeffs]


def commitment_eval(commitments: Sequence[int], x: int) -> int:
    """prod_j C_j^{x^j} mod P  ==  G^{A(x)} for an honest dealer."""
    acc = 1
    xp = 1  # x^j mod Q
    for c_j in commitments:
        acc = (acc * pow(c_j, xp, P)) % P
        xp = (xp * x) % Q
    return acc


def verify_share(index: int, value: int, commitments: Sequence[int]) -> bool:
    """Feldman check: G^value == prod_j C_j^{index^j} (mod P)."""
    return pow(G, value % Q, P) == commitment_eval(commitments, index)


def feldman_deal(
    secret: int, xs: Sequence[int], k: int
) -> Tuple[Dict[int, VShare], List[int], List[int]]:
    """Feldman-VSS split of `secret` at coords `xs`, threshold k.

    Returns (shares, commitments, coeffs). `commitments` are public; `coeffs`
    are the dealer's private polynomial (returned only so tests/re-sharers that
    legitimately own the secret can drive the sim -- never transmitted).
    """
    if not 1 < k <= len(xs):
        raise ValueError("require 1 < k <= number of shares")
    if len(set(xs)) != len(xs) or any(x % Q == 0 for x in xs):
        raise ValueError("x-coords must be distinct and nonzero mod Q")
    coeffs = [secret % Q] + [_rand_field() for _ in range(k - 1)]
    commitments = commit(coeffs)
    shares = {x: VShare(index=x, value=_poly_eval(coeffs, x)) for x in xs}
    return shares, commitments, coeffs


def lagrange_at_zero(xs: Sequence[int]) -> Dict[int, int]:
    """lambda_i (mod Q) with A(0) = sum_i lambda_i * A(x_i)."""
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate x-coordinates")
    out: Dict[int, int] = {}
    for xi in xs:
        num, den = 1, 1
        for xj in xs:
            if xi == xj:
                continue
            num = (num * (-xj)) % Q          # (0 - x_j)
            den = (den * (xi - xj)) % Q      # (x_i - x_j)
        out[xi] = (num * pow(den, -1, Q)) % Q
    return out


def combine(shares: Sequence[VShare]) -> int:
    """Reconstruct the secret via Lagrange interpolation at 0 (mod Q).

    This is the ONLY routine that assembles s. The re-sharing protocol never
    calls it; only tests do, to check the outcome.
    """
    if not shares:
        raise ValueError("no shares")
    lam = lagrange_at_zero([s.index for s in shares])
    return sum(lam[s.index] * s.value for s in shares) % Q


# ---------------------------------------------------------------------------
# Verifiable re-sharing
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class DealerBroadcast:
    """What an old holder publishes/sends when acting as a re-share dealer.

    commitments : Feldman commitments to its fresh sub-share polynomial Q_i.
    subshares   : {new_party_x : Q_i(new_party_x)} -- in reality each is sent
                  privately to its addressee over an authenticated channel.
    """

    dealer_index: int
    commitments: List[int]
    subshares: Dict[int, int]


@dataclass
class Complaint:
    """A new party's accusation that a specific dealer sent a bad sub-share."""

    accuser_new_index: int
    accused_dealer_index: int
    reason: str


@dataclass
class ReshareResult:
    new_shares: List[VShare]
    complaints: List[Complaint] = field(default_factory=list)
    disqualified: List[int] = field(default_factory=list)   # dealer indices
    qualified: List[int] = field(default_factory=list)      # dealer indices


def reshare_deal(
    old_index: int,
    my_old_value: int,
    *,
    new_indices: Sequence[int],
    k_new: int,
) -> Tuple[DealerBroadcast, List[int]]:
    """An old holder re-shares ITS share as a Feldman dealer.

    Uses only this party's own share value (never any other's), so it cannot
    reconstruct s. Returns the public DealerBroadcast plus the private coeffs
    (kept locally, never transmitted).
    """
    shares, commitments, coeffs = feldman_deal(my_old_value, list(new_indices), k_new)
    bc = DealerBroadcast(
        dealer_index=old_index,
        commitments=commitments,
        subshares={x: sh.value for x, sh in shares.items()},
    )
    return bc, coeffs


def verify_subshare(
    bc: DealerBroadcast,
    new_index: int,
    *,
    dealer_old_index: int,
    orig_commitments: Optional[Sequence[int]] = None,
) -> Tuple[bool, str]:
    """New party's verification of one dealer's sub-share addressed to it.

    Two checks, both attributable to `bc.dealer_index`:
      (A) Feldman consistency: the sub-share lies on the committed polynomial.
      (B) constant-term binding (optional, needs the ORIGINAL commitments):
          the dealer's committed Q_i(0) equals G^{s_i} predicted for the
          dealer's own old share by the original secret's commitments V.
    Returns (ok, reason). reason == "" iff ok.
    """
    sub = bc.subshares.get(new_index)
    if sub is None:
        return False, f"dealer {bc.dealer_index}: no sub-share for party {new_index}"
    # (A) Feldman consistency of the sub-share against the dealer's commitments.
    if not verify_share(new_index, sub, bc.commitments):
        return False, (
            f"dealer {bc.dealer_index}: sub-share to party {new_index} FAILS "
            f"Feldman check g^s != prod C_j^(x^j)"
        )
    # (B) binding to the dealer's true old share via the original commitments.
    if orig_commitments is not None:
        predicted = commitment_eval(orig_commitments, dealer_old_index)  # G^{s_i}
        if bc.commitments[0] != predicted:
            return False, (
                f"dealer {bc.dealer_index}: committed constant term C_0 != G^"
                f"{{s_{dealer_old_index}}} -- re-shared a WRONG secret"
            )
    return True, ""


def reshare_verifiable(
    old_shares: Sequence[VShare],
    *,
    new_indices: Sequence[int],
    k_old: int,
    k_new: int,
    orig_commitments: Optional[Sequence[int]] = None,
    tamper: Optional[Dict[int, "DealerBroadcast"]] = None,
) -> ReshareResult:
    """Run one verifiable re-share from an old committee to a new committee.

    old_shares      : participating old holders (>= k_old of them).
    new_indices     : x-coords of the new committee.
    k_old / k_new   : old and new thresholds.
    orig_commitments: public Feldman commitments to the ORIGINAL secret poly,
                      enabling the constant-term binding check (B). Recommended.
    tamper          : test hook mapping dealer_index -> a replacement (malicious)
                      DealerBroadcast, to inject a cheating dealer.

    Every sub-share is verified before aggregation. Dealers that fail any check
    are DISQUALIFIED and named in `complaints`. New shares are aggregated only
    from qualified dealers, Lagrange-weighted over that qualified set, so the
    secret is preserved as long as >= k_old honest dealers remain qualified.
    NEVER calls combine().
    """
    epochs = {s.epoch for s in old_shares}
    if len(epochs) != 1:
        raise ValueError("participating old shares must share one epoch")
    new_epoch = epochs.pop() + 1

    # Phase 1: every old holder deals sub-shares (as a Feldman dealer).
    broadcasts: Dict[int, DealerBroadcast] = {}
    for s in old_shares:
        bc, _ = reshare_deal(s.index, s.value, new_indices=new_indices, k_new=k_new)
        if tamper and s.index in tamper:
            bc = tamper[s.index]  # inject the malicious broadcast
        broadcasts[s.index] = bc

    # Phase 2: every new party verifies every dealer's sub-share to it.
    complaints: List[Complaint] = []
    accused: set[int] = set()
    for new_x in new_indices:
        for dealer_x, bc in broadcasts.items():
            ok, reason = verify_subshare(
                bc, new_x, dealer_old_index=dealer_x, orig_commitments=orig_commitments
            )
            if not ok:
                complaints.append(Complaint(new_x, dealer_x, reason))
                accused.add(dealer_x)

    qualified = [s.index for s in old_shares if s.index not in accused]
    if len(qualified) < k_old:
        raise ValueError(
            f"only {len(qualified)} honest dealers left (need >= k_old={k_old}); "
            f"disqualified={sorted(accused)}"
        )

    # Phase 3: aggregate ONLY qualified dealers, weighted over the qualified set.
    lam = lagrange_at_zero(qualified)
    new_shares: List[VShare] = []
    for new_x in new_indices:
        acc = 0
        for dealer_x in qualified:
            acc = (acc + lam[dealer_x] * broadcasts[dealer_x].subshares[new_x]) % Q
        new_shares.append(VShare(index=new_x, value=acc, epoch=new_epoch))

    return ReshareResult(
        new_shares=new_shares,
        complaints=complaints,
        disqualified=sorted(accused),
        qualified=sorted(qualified),
    )
