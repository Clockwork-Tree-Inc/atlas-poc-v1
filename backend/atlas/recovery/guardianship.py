"""Guardianship — the recovery net (TRUST_LAYER.md #4/#5).

The point is not *guardians* so much as *guardianship*: a **private** set (only YOU know the
full membership) of parties who each hold a share of your recovery threshold. Two kinds:

  * SILENT custodians — passive, opaque device-node shares. They hold a share, do nothing,
    and need not even know they are guardians. Anti-collusion (they cannot conspire if they
    do not know each other, or that they are guardians) and anti-coercion (nothing to coerce
    out of a node that only stores an opaque share).
  * WITTING guardians — humans who know they are guardians and can VETO (or must APPROVE) a
    recovery. The human-in-the-loop gate.

STRUCTURAL INVARIANT (#4), enforced at policy construction AND defensively at reconstruction:
**no all-institutional subset reaches threshold.** If the number of institutional guardians
(operators/servers/jurisdictions) is < m, then every m-subset must contain at least one
non-institutional party — so servers/operators ALONE can never recover you. This is what makes
recovery subpoena- and coercion-resistant: a non-institutional party (a personal node, or a
live recovery person acting as a witting guardian) is always required.

CONFIGURABLE m-of-n (#5): the threshold is user policy, validated against the invariant.

This module adds POLICY, not new crypto — it composes `recovery.threshold_seal` (m-of-n ∧
user half). Because there is no new keyed derivation here, there are no new parity vectors;
the byte-level seal is already parity-covered by threshold_seal. The Swift mirror reproduces
the *logic* (invariant + veto) with native tests.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Sequence

from ..crypto.primitives import H
from ..crypto.sign import HybridSigPublic, verify
from . import threshold_seal as ts
from .threshold_seal import (
    Custodian,
    CustodianShare,
    SealedSketch,
    StorageLocation,
    ThresholdPolicy,
)

_CARD = b"atlas/guardianship/card/v1"


def card_recovery_message(context: bytes) -> bytes:
    """The message the SE recovery card signs to authorize a guardian recovery, bound to the
    sealed sketch's context so a card authorization cannot be replayed across recoveries. On real
    hardware the card only produces this signature behind its live-holder gate (fingerprint+ECG)."""
    return H(_CARD, context)


class GuardianshipError(Exception):
    """Base class — every guardianship failure is fail-closed (raises)."""


class InstitutionalThresholdError(GuardianshipError):
    """An all-institutional subset could reach (or was presented at) threshold — forbidden.
    Servers/operators alone must never be able to recover a user."""


class WittingVeto(GuardianshipError):
    """A witting guardian vetoed the recovery — a human said no."""


class ApprovalsNotMet(GuardianshipError):
    """Fewer witting approvals than the policy requires."""


class CardRequired(GuardianshipError):
    """The user's policy requires the SE recovery card for guardian recovery and a valid card
    signature was not presented — social recovery fails closed, dropping the user to in-person."""


class GuardianKind(str, Enum):
    SILENT = "silent"    # passive device node; holds a share, no interaction, may be unaware
    WITTING = "witting"  # a human who knows they are a guardian; can veto / must approve


@dataclass(frozen=True)
class Guardian:
    """One member of the guardianship. `custodian` carries the opaque label + institutional
    flag (from threshold_seal — nothing here reveals who a guardian is). `kind` distinguishes a
    silent device-node from a witting human."""

    custodian: Custodian
    kind: GuardianKind

    @property
    def label(self) -> str:
        return self.custodian.label

    @property
    def institutional(self) -> bool:
        return self.custodian.institutional


@dataclass(frozen=True)
class GuardianShare:
    """One guardian's share of the recovery threshold."""

    guardian: Guardian
    share: ts.shamir.Share


@dataclass(frozen=True)
class GuardianshipPolicy:
    """Configurable m-of-n over a private guardian set (#5), with the anti-collusion invariant
    (#4) enforced at construction. `min_witting_approvals` optionally requires human sign-off."""

    guardians: tuple[Guardian, ...]
    m: int
    min_witting_approvals: int = 0
    # The user's authenticity choice (mirrors tiers.RecoveryPolicy.require_card_for_social): when
    # True, guardian recovery ALSO requires a valid signature from the SE recovery card, so a
    # guardian quorum alone cannot reopen the sketch and losing the card forces in-person recovery.
    require_card: bool = False
    card_pub: Optional[HybridSigPublic] = None

    def __post_init__(self) -> None:
        # validates 1 < m <= n < 256
        ThresholdPolicy(n=len(self.guardians), m=self.m)
        institutional = sum(1 for g in self.guardians if g.institutional)
        if institutional >= self.m:
            raise InstitutionalThresholdError(
                f"{institutional} institutional guardians >= threshold {self.m}: an "
                f"all-institutional subset could recover you (need institutional_count < m)")
        witting = sum(1 for g in self.guardians if g.kind is GuardianKind.WITTING)
        if not 0 <= self.min_witting_approvals <= witting:
            raise GuardianshipError(
                f"min_witting_approvals={self.min_witting_approvals} outside [0, {witting}]")
        if self.require_card and self.card_pub is None:
            raise GuardianshipError("require_card is set but no card_pub was provided")

    @property
    def n(self) -> int:
        return len(self.guardians)

    @property
    def threshold_policy(self) -> ThresholdPolicy:
        return ThresholdPolicy(n=self.n, m=self.m)

    def _witting_labels(self) -> set[str]:
        return {g.label for g in self.guardians if g.kind is GuardianKind.WITTING}


def seal_under_guardianship(
    secret: bytes,
    *,
    user_half: bytes,
    policy: GuardianshipPolicy,
    storage: StorageLocation,
    context: bytes = b"",
) -> tuple[SealedSketch, List[GuardianShare]]:
    """Seal `secret` under (user_half ∧ m-of-n guardians). Returns the opaque `SealedSketch`
    (store anywhere) and one `GuardianShare` per guardian (distribute to each)."""
    sealed, custodian_shares = ts.seal(
        secret,
        user_half=user_half,
        custodians=[g.custodian for g in policy.guardians],
        policy=policy.threshold_policy,
        storage=storage,
        context=context,
    )
    guardian_shares = [GuardianShare(guardian=g, share=cs.share)
                       for g, cs in zip(policy.guardians, custodian_shares)]
    return sealed, guardian_shares


def reconstruct_under_guardianship(
    sealed: SealedSketch,
    *,
    user_half: bytes,
    presented_shares: Sequence[GuardianShare],
    policy: GuardianshipPolicy,
    witting_approvals: Sequence[str] = (),
    witting_vetoes: Sequence[str] = (),
    card_signature: Optional[bytes] = None,
) -> bytes:
    """Reopen a guardianship-sealed secret. Order of checks (all fail-closed):

      1. WITTING VETO — any valid veto from a witting guardian aborts (a human said no).
      2. WITTING APPROVAL — at least `min_witting_approvals` valid approvals from witting
         guardians (only real witting members count; unknown labels are ignored).
      3. CARD — if `policy.require_card`, a valid signature from the SE recovery card over
         `card_recovery_message(sealed.context)`; without it social recovery fails closed and the
         user drops to the in-person floor. This is what makes the card requirement cryptographically
         BINDING, not merely a tier-selector hint.
      4. ANTI-COLLUSION — the presented share set must include a non-institutional guardian
         (defence-in-depth on the construction-time invariant); an all-institutional set is
         rejected even if it meets the numeric threshold.
      5. THRESHOLD — hand off to `threshold_seal.unseal` (needs the user half + ≥ m shares;
         below threshold raises `ThresholdNotMet`, a wrong factor raises `UnsealFailed`)."""
    witting = policy._witting_labels()

    real_vetoes = {lbl for lbl in witting_vetoes if lbl in witting}
    if real_vetoes:
        raise WittingVeto(f"{len(real_vetoes)} witting guardian(s) vetoed recovery")

    real_approvals = {lbl for lbl in witting_approvals if lbl in witting}
    if len(real_approvals) < policy.min_witting_approvals:
        raise ApprovalsNotMet(
            f"need {policy.min_witting_approvals} witting approvals, got {len(real_approvals)}")

    if policy.require_card:
        if card_signature is None or not verify(
                policy.card_pub, card_recovery_message(sealed.context), card_signature):
            raise CardRequired(
                "policy requires the SE recovery card, but no valid card signature was presented")

    if presented_shares and all(gs.guardian.institutional for gs in presented_shares):
        raise InstitutionalThresholdError(
            "presented shares are all institutional — a non-institutional party is required")

    custodian_shares = [CustodianShare(custodian=gs.guardian.custodian, share=gs.share)
                        for gs in presented_shares]
    return ts.unseal(sealed, user_half=user_half, custodian_shares=custodian_shares)


def rotate_guardianship(
    sealed: SealedSketch,
    *,
    user_half: bytes,
    presented_shares: Sequence[GuardianShare],
    old_policy: GuardianshipPolicy,
    new_policy: GuardianshipPolicy,
    storage: StorageLocation,
    context: bytes = b"",
    card_signature: Optional[bytes] = None,
    witting_approvals: Sequence[str] = (),
) -> tuple[SealedSketch, List[GuardianShare]]:
    """Revoke / rotate the guardian set: reconstruct the secret with a CURRENT quorum, then RE-SEAL
    it under `new_policy` — which may drop a revoked guardian, add a new one, change m, or flip the
    card requirement. The old shares become useless against the returned sketch, so this is how
    "revoke a share anytime while alive" works: the holder re-provisions, the secret never leaves the
    client, and no operator is involved. Because it goes through `reconstruct_under_guardianship`
    first, rotation is itself gated by the *old* recovery policy (a valid quorum + user half [+ card]
    is required to rotate), so an attacker cannot use rotation to bypass recovery."""
    secret = reconstruct_under_guardianship(
        sealed, user_half=user_half, presented_shares=presented_shares, policy=old_policy,
        witting_approvals=witting_approvals, card_signature=card_signature)
    return seal_under_guardianship(secret, user_half=user_half, policy=new_policy,
                                   storage=storage, context=context)
