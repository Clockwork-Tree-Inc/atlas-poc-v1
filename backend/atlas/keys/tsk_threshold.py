"""Configurable t-of-n threshold protection for the TSK (§7.3, Inv 22).

Generalizes the fixed 2-of-2 (user_half ∧ server_half, `keys/identity.py`) into a
USER-CHOSEN threshold over an ARBITRARY holder set. The TSK seed is Shamir-split
(GF(256), reused from `crypto.shamir`) into `n` shares held by `n` holders; any
`m` reconstruct it. Default 2-of-3: Wallet-SE / USB / Server-HSM.

"As many of as many as you want" = any policy with 1 < m <= n < 256, subject to
the ANTI-CAPTURE / ANTI-REMOTE-RECOVERY invariant reused from the guardianship
model (`recovery/guardianship.py`): **no all-institutional subset reaches
threshold.** An institutional holder (a server/operator/remotely-reachable HSM)
is reachable by subpoena/compromise without the user's physical presence; if a
quorum could be formed from institutional holders alone, recovery would be a
remote-takeover path. Requiring institutional_count < m guarantees every m-subset
contains at least one NON-institutional (present/personal/accountable) holder — a
Wallet-SE in hand, a USB, a recovery card, a live guardian.

REUSE (do NOT hand-roll): Shamir (`crypto.shamir`), the policy/holder types
(`recovery.threshold_seal.ThresholdPolicy`/`Custodian`). This module is the TSK
PRIMARY split; `recovery.threshold_seal` is the recovery SEAL (secret under
user_half ∧ custodians) — related but distinct shapes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence

from ..crypto import shamir
from ..recovery.threshold_seal import Custodian, ThresholdPolicy


class TSKThresholdError(Exception):
    """Base class — every failure is fail-closed (raises)."""


class AllInstitutionalQuorum(TSKThresholdError):
    """A subset of only institutional/remote holders could reach (or was presented
    at) threshold — forbidden. Servers/operators alone must never reconstruct the
    TSK (= the anti-remote-recovery invariant, guardianship #4)."""


class HolderCountMismatch(TSKThresholdError):
    """The number of holders did not match the policy's n."""


@dataclass(frozen=True)
class TSKShare:
    """One holder's share of the TSK seed. `holder.institutional` carries the
    present-vs-remote classification the invariant is enforced on."""

    holder: Custodian
    share: shamir.Share


#: Default 2-of-3: two present/personal holders + one institutional (server HSM).
#: institutional_count (1) < m (2) -> every 2-subset includes a present holder.
DEFAULT_POLICY = ThresholdPolicy(n=3, m=2)
DEFAULT_HOLDERS: tuple[Custodian, ...] = (
    Custodian(label="wallet-se", institutional=False),   # the phone's Secure Enclave, in hand
    Custodian(label="usb", institutional=False),          # a physical USB / recovery card
    Custodian(label="server-hsm", institutional=True),    # the blind server HSM (remote)
)


def _enforce_invariant(policy: ThresholdPolicy, holders: Sequence[Custodian]) -> None:
    if len(holders) != policy.n:
        raise HolderCountMismatch(f"policy expects n={policy.n} holders, got {len(holders)}")
    institutional = sum(1 for h in holders if h.institutional)
    if institutional >= policy.m:
        raise AllInstitutionalQuorum(
            f"{institutional} institutional holders >= threshold m={policy.m}: an "
            "all-institutional subset could recover the TSK remotely (forbidden)")


def split_tsk(
    tsk_seed: bytes,
    *,
    policy: ThresholdPolicy = DEFAULT_POLICY,
    holders: Sequence[Custodian] = DEFAULT_HOLDERS,
) -> List[TSKShare]:
    """Split `tsk_seed` into `policy.n` shares (any `policy.m` reconstruct), one per
    holder. Enforces the anti-remote-recovery invariant before splitting."""
    if len(tsk_seed) < 32:
        raise ValueError("tsk_seed must be >= 32 bytes")
    _enforce_invariant(policy, holders)
    shares = shamir.split(tsk_seed, n=policy.n, k=policy.m)
    return [TSKShare(holder=h, share=s) for h, s in zip(holders, shares)]


def reconstruct_tsk(shares: Sequence[TSKShare]) -> bytes:
    """Reconstruct the TSK seed from >= m shares. Defensive re-check of the invariant
    at reconstruction: an all-institutional presented quorum is refused even if a
    caller assembled one, so the check cannot be bypassed post-split."""
    if len(shares) >= 2 and all(s.holder.institutional for s in shares):
        raise AllInstitutionalQuorum(
            "refusing to reconstruct from an all-institutional quorum")
    return shamir.combine([s.share for s in shares])
