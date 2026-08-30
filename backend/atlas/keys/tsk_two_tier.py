"""Two-tier TSK recovery — `Shamir(your-half) ∧ Shamir(server-half)`, both mandatory.

Strengthens the flat `tsk_threshold.split_tsk` (any m-of-n, with an anti-all-institutional
*check*) into a construction where the anti-institutional property is STRUCTURAL, not a
policy check:

    TSK seed  =  user_half  XOR  server_half
    user_half   -> Shamir t-of-n over YOUR holders   (phone SE, USB, your other devices, contact)
    server_half -> Shamir k-of-m over the server side (nodes / operators / HSM)

Reconstruct needs **t of your holders AND k of the server side** — because the seed is an
XOR of two independent secrets, a threshold of EACH half is required:

  * The server/institutional side only ever holds shares of `server_half`. `server_half`
    alone is an independent random value that reveals NOTHING about the seed (XOR one-time
    pad with `user_half`). So no subset of the server side — even ALL of it — can ever
    reconstruct the TSK. "Can never be constructed without your parameters" is now a
    property of the math, not a rule we remember to enforce.
  * Symmetrically, your holders alone can't either (they lack `server_half`), so a stolen
    phone+USB is not enough without the server quorum.
  * Within each half it's a real threshold, so losing up to (n-t) of your holders and up to
    (m-k) server holders still recovers. Fault-tolerant on both sides.

This is the PRIMARY recovery split. `recovery.threshold_seal` (secret under
user_half ∧ custodians) is the recovery SEAL and composes with this (its `user_half` can be
the value reconstructed here). Reuses Shamir + the policy/holder types; no hand-rolled crypto.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence, Tuple

from ..crypto import shamir
from ..recovery.threshold_seal import Custodian, ThresholdPolicy


class TwoTierError(Exception):
    """Base — every failure is fail-closed (raises)."""


class ThresholdNotMet(TwoTierError):
    """Fewer than the required shares were presented for one of the two halves."""


class HolderClassError(TwoTierError):
    """A user holder was marked institutional, or a server holder non-institutional —
    the two-tier structure depends on the split being your-side vs server-side."""


@dataclass(frozen=True)
class TSKShare:
    holder: Custodian
    share: shamir.Share


@dataclass(frozen=True)
class TwoTierShares:
    """The full share set: your-half shares + server-half shares, each with its policy."""
    user_shares: List[TSKShare]
    server_shares: List[TSKShare]
    user_policy: ThresholdPolicy
    server_policy: ThresholdPolicy


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def split_tsk_two_tier(
    tsk_seed: bytes,
    *,
    user_holders: Sequence[Custodian],
    server_holders: Sequence[Custodian],
    user_policy: ThresholdPolicy,
    server_policy: ThresholdPolicy,
    rng=None,
) -> TwoTierShares:
    """Split `tsk_seed` into your-half (Shamir t-of-n over YOUR holders) and server-half
    (Shamir k-of-m over the server side). Both halves are required to reconstruct.

    Enforces the class split: `user_holders` must all be non-institutional (things you
    hold), `server_holders` all institutional (nodes/operators). That split is what makes
    the anti-institutional property structural."""
    if len(tsk_seed) < 32:
        raise ValueError("tsk_seed must be >= 32 bytes")
    if len(user_holders) != user_policy.n:
        raise ValueError(f"user_policy expects n={user_policy.n}, got {len(user_holders)}")
    if len(server_holders) != server_policy.n:
        raise ValueError(f"server_policy expects n={server_policy.n}, got {len(server_holders)}")
    if any(h.institutional for h in user_holders):
        raise HolderClassError("user_holders must all be non-institutional (things you hold)")
    if not all(h.institutional for h in server_holders):
        raise HolderClassError("server_holders must all be institutional (nodes/operators)")

    from ..crypto.primitives import random_bytes
    _rng = rng or random_bytes
    user_half = _rng(len(tsk_seed))                 # full-entropy; server_half is the XOR complement
    server_half = _xor(tsk_seed, user_half)

    user_raw = shamir.split(user_half, n=user_policy.n, k=user_policy.m)
    server_raw = shamir.split(server_half, n=server_policy.n, k=server_policy.m)
    return TwoTierShares(
        user_shares=[TSKShare(h, s) for h, s in zip(user_holders, user_raw)],
        server_shares=[TSKShare(h, s) for h, s in zip(server_holders, server_raw)],
        user_policy=user_policy, server_policy=server_policy,
    )


def reconstruct_tsk_two_tier(
    *,
    user_shares: Sequence[TSKShare],
    server_shares: Sequence[TSKShare],
    user_policy: ThresholdPolicy,
    server_policy: ThresholdPolicy,
) -> bytes:
    """Rebuild the TSK from >= t of YOUR shares AND >= k server shares. Fail-closed if
    either half is below threshold — and crucially, the server side alone (any number of
    server shares, no user shares) can NEVER reconstruct, because it only carries
    server_half, which is independent of the seed."""
    if len(user_shares) < user_policy.m:
        raise ThresholdNotMet(
            f"need {user_policy.m} of your holders, got {len(user_shares)} "
            "(the TSK can never be rebuilt without a threshold of YOUR holders)")
    if len(server_shares) < server_policy.m:
        raise ThresholdNotMet(
            f"need {server_policy.m} server holders, got {len(server_shares)}")
    user_half = shamir.combine([s.share for s in user_shares])
    server_half = shamir.combine([s.share for s in server_shares])
    return _xor(user_half, server_half)


#: A sane default that matches the app's intent: your-half 2-of-3 (phone SE, USB, contact),
#: server-half 1-of-1 stays a *threshold* only if k>1 — Shamir needs k>1, so the server side
#: uses k-of-m with m>=2 (e.g. 2-of-3 nodes). Callers pick the real policies.
def default_holders() -> Tuple[List[Custodian], List[Custodian]]:
    user = [
        Custodian(label="phone-se", institutional=False),
        Custodian(label="usb", institutional=False),
        Custodian(label="contact", institutional=False),
    ]
    server = [
        Custodian(label="node-a", institutional=True),
        Custodian(label="node-b", institutional=True),
        Custodian(label="node-c", institutional=True),
    ]
    return user, server
