"""Reference simulation of PROACTIVE / RE-SHARING for Shamir threshold shares.

PURE-PYTHON REFERENCE ONLY -- NOT production crypto. This validates a *design
addition* for the Atlas PoC: dynamically changing threshold membership (add /
remove a share-holder, or just refresh) of a k-of-n Shamir split of the root of
trust WITHOUT ever reconstructing the secret.

It reuses the existing audited-style GF(256) Shamir core unchanged:

    from atlas.crypto import shamir, primitives

The scheme (standard polynomial re-sharing, a.k.a. the resharing step of
Herzberg-style proactive secret sharing / Desmedt-Jajodia redistribution):

  Secret s is the constant term of a degree (k-1) polynomial P, with old share
  of party i being s_i = P(x_i).

  1. DEAL. Each *old* party i, using ONLY its own share s_i, picks a fresh
     random degree (k'-1) polynomial Q_i with Q_i(0) = s_i and hands sub-share
     Q_i(x'_j) to each *new* party j. (This is exactly shamir.split(s_i).)

  2. AGGREGATE. Each *new* party j, having received one sub-share from each old
     party in the chosen participating set S (|S| >= k), forms its new share as
     the Lagrange-weighted sum
            s'_j = sum_{i in S} lambda_i^S * Q_i(x'_j)
     where lambda_i^S are the Lagrange coefficients at 0 for the set S.

  Then the new committee's shares s'_j lie on the polynomial
            P'(x) = sum_{i in S} lambda_i^S * Q_i(x)
  which has fresh random coefficients but the SAME constant term:
            P'(0) = sum_{i in S} lambda_i^S * Q_i(0)
                  = sum_{i in S} lambda_i^S * s_i = P(0) = s.
  So any k' of the new committee reconstruct the same s. New threshold k' and
  size n' are chosen freely (add / remove members, change threshold).

KEY STRUCTURAL PROPERTY: no party ever holds >= k shares of s at any point.
Reconstructing a party's *sub-shares* only yields that party's individual old
share s_i, never s. shamir.combine (the only routine that assembles s) is NEVER
called during the protocol -- test_reshare.py asserts this by instrumentation.

SIMPLIFICATIONS (labelled honestly):
  * The transport ("each party hands sub-share to party j") is modelled as
    in-process dict passing. A real deployment needs authenticated, encrypted
    channels (Atlas already has kem/sign/AEAD primitives for this).
  * Dealers are assumed HONEST. This scheme is NOT verifiable: a malicious old
    dealer can hand inconsistent sub-shares and corrupt a new share undetectably.
    Production needs a *verifiable* re-sharing (Feldman/Pedersen VSS commitments).
    See findings in the report.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Sequence

from atlas.crypto import primitives, shamir

# Reuse the existing GF(256) field ops from the audited-style core rather than
# re-implementing them, so the sim shares one field with atlas.
_gf_mul = shamir._mul
_gf_div = shamir._div


def _split_at(secret: bytes, xs: Sequence[int], k: int) -> Dict[int, shamir.Share]:
    """Shamir-split `secret`, evaluating the polynomial at the GIVEN x-coords.

    shamir.split hard-codes x = 1..n; re-sharing to a non-contiguous committee
    (e.g. {1,2,4} after removing party 3) requires evaluating each dealer's
    polynomial at the new parties' ACTUAL x-coordinates. This mirrors
    shamir.split byte-for-byte (independent random poly per byte, Horner eval)
    but over an arbitrary x-set, reusing atlas's GF(256) _mul and CSPRNG.
    """
    if not 1 < k <= len(xs):
        raise ValueError("require 1 < k <= number of shares")
    if any(not (1 <= x <= 255) for x in xs) or len(set(xs)) != len(xs):
        raise ValueError("x-coords must be distinct and in 1..255")
    ys: Dict[int, bytearray] = {x: bytearray() for x in xs}
    for byte in secret:
        coeffs = [byte] + list(primitives.random_bytes(k - 1))
        for x in xs:
            acc = 0
            for c in reversed(coeffs):  # Horner, identical to shamir.split
                acc = _gf_mul(acc, x) ^ c
            ys[x].append(acc)
    return {x: shamir.Share(index=x, y=bytes(ys[x])) for x in xs}


# ---------------------------------------------------------------------------
# Epoch / generation tagging (property 4: old shares cannot be mixed with new)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class EpochShare:
    """A Shamir share tagged with the committee generation it belongs to.

    Each re-share bumps the epoch. Shares from different epochs lie on different
    polynomials (fresh coefficients), so combining across epochs is not only
    policy-forbidden here but also mathematically meaningless -- it silently
    yields garbage. The epoch tag turns that silent corruption into a hard error.
    """

    epoch: int
    share: shamir.Share

    @property
    def index(self) -> int:
        return self.share.index


def epoch_combine(shares: Sequence[EpochShare]) -> bytes:
    """combine() that refuses to mix generations (generation separation)."""
    if not shares:
        raise ValueError("no shares")
    epochs = {s.epoch for s in shares}
    if len(epochs) != 1:
        raise ValueError(f"refusing to combine shares from different epochs: {sorted(epochs)}")
    return shamir.combine([s.share for s in shares])


# ---------------------------------------------------------------------------
# Lagrange coefficients at x = 0 over GF(256) for a chosen participating set
# ---------------------------------------------------------------------------
def lagrange_coeffs_at_zero(xs: Sequence[int]) -> Dict[int, int]:
    """lambda_i such that P(0) = sum_i lambda_i * P(x_i) for the set {xs}.

    Same arithmetic as shamir.combine's interpolation, exposed as coefficients
    so we can weight *polynomials* (sub-shares) instead of scalar y-values.
    """
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate x-coordinates")
    coeffs: Dict[int, int] = {}
    for xi in xs:
        num, den = 1, 1
        for xj in xs:
            if xi == xj:
                continue
            num = _gf_mul(num, xj)        # (0 - x_j) == x_j in GF(2^8)
            den = _gf_mul(den, xi ^ xj)   # (x_i - x_j)
        coeffs[xi] = _gf_div(num, den)
    return coeffs


# ---------------------------------------------------------------------------
# Phase 1 -- performed LOCALLY by each old share-holder, over its OWN share only
# ---------------------------------------------------------------------------
def deal_subshares(
    my_old_share: shamir.Share,
    *,
    new_indices: Sequence[int],
    k_new: int,
) -> Dict[int, shamir.Share]:
    """Old party splits ITS share into sub-shares for the new committee.

    Input is a single share (this party's). This function never has access to
    any other party's share, so it cannot reconstruct s. Output maps each new
    party index -> the sub-share destined for it.
    """
    # Evaluate this dealer's fresh polynomial at each NEW party's actual
    # x-coordinate, so sub-share for party j is exactly Q_i(x'_j).
    return _split_at(my_old_share.y, list(new_indices), k_new)


# ---------------------------------------------------------------------------
# Phase 2 -- performed LOCALLY by each new share-holder, from sub-shares it got
# ---------------------------------------------------------------------------
def aggregate_new_share(
    my_new_index: int,
    subshares_from_old: Dict[int, shamir.Share],
    lagrange: Dict[int, int],
    *,
    new_epoch: int,
) -> EpochShare:
    """New party sums the Lagrange-weighted sub-shares it received into a share.

    subshares_from_old: {old_party_x : sub-share this new party received}
    lagrange:           {old_party_x : lambda coefficient} for the SAME set.
    The new party never sees any old share directly, only weighted sub-shares.
    """
    if set(subshares_from_old) != set(lagrange):
        raise ValueError("participating set mismatch between sub-shares and coefficients")
    length = len(next(iter(subshares_from_old.values())).y)
    acc = bytearray(length)
    for old_x, sub in subshares_from_old.items():
        lam = lagrange[old_x]
        if len(sub.y) != length:
            raise ValueError("inconsistent sub-share length")
        for pos in range(length):
            acc[pos] ^= _gf_mul(sub.y[pos], lam)  # GF add == XOR
    return EpochShare(epoch=new_epoch, share=shamir.Share(index=my_new_index, y=bytes(acc)))


# ---------------------------------------------------------------------------
# Orchestration harness (models the network; the crypto above is per-party)
# ---------------------------------------------------------------------------
def reshare(
    old_shares: Sequence[EpochShare],
    *,
    new_indices: Sequence[int],
    k_new: int,
) -> List[EpochShare]:
    """Re-share from an old committee to a new committee.

    old_shares: the participating subset S of the current committee (>= k of them).
    new_indices: x-coordinates of the new committee (add/remove -> change this set).
    k_new: new threshold.

    Returns the new committee's EpochShares (epoch = old epoch + 1). This is a
    *simulation harness*: the dict shuffling models an authenticated network,
    while deal_subshares / aggregate_new_share are what real parties would run
    locally. Nothing here ever calls shamir.combine.
    """
    epochs = {s.epoch for s in old_shares}
    if len(epochs) != 1:
        raise ValueError("participating old shares must share one epoch")
    old_epoch = epochs.pop()
    new_epoch = old_epoch + 1

    old_xs = [s.index for s in old_shares]
    lagrange = lagrange_coeffs_at_zero(old_xs)

    # Phase 1: every old party deals sub-shares for the whole new committee.
    # dealt[old_x][new_x] = sub-share
    dealt: Dict[int, Dict[int, shamir.Share]] = {
        s.index: deal_subshares(s.share, new_indices=new_indices, k_new=k_new)
        for s in old_shares
    }

    # Phase 2: every new party aggregates the sub-shares addressed to it.
    new_shares: List[EpochShare] = []
    for new_x in new_indices:
        subs_for_j = {old_x: dealt[old_x][new_x] for old_x in old_xs}
        new_shares.append(
            aggregate_new_share(new_x, subs_for_j, lagrange, new_epoch=new_epoch)
        )
    return new_shares
