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
from typing import List, Sequence

from . import threshold_seal as ts
from .threshold_seal import (
    Custodian,
    CustodianShare,
    SealedSketch,
    StorageLocation,
    ThresholdPolicy,
)


class GuardianshipError(Exception):
    """Base class — every guardianship failure is fail-closed (raises)."""


class InstitutionalThresholdError(GuardianshipError):
    """An all-institutional subset could reach (or was presented at) threshold — forbidden.
    Servers/operators alone must never be able to recover a user."""


class WittingVeto(GuardianshipError):
    """A witting guardian vetoed the recovery — a human said no."""


class ApprovalsNotMet(GuardianshipError):
    """Fewer witting approvals than the policy requires."""


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
) -> bytes:
    """Reopen a guardianship-sealed secret. Order of checks (all fail-closed):

      1. WITTING VETO — any valid veto from a witting guardian aborts (a human said no).
      2. WITTING APPROVAL — at least `min_witting_approvals` valid approvals from witting
         guardians (only real witting members count; unknown labels are ignored).
      3. ANTI-COLLUSION — the presented share set must include a non-institutional guardian
         (defence-in-depth on the construction-time invariant); an all-institutional set is
         rejected even if it meets the numeric threshold.
      4. THRESHOLD — hand off to `threshold_seal.unseal` (needs the user half + ≥ m shares;
         below threshold raises `ThresholdNotMet`, a wrong factor raises `UnsealFailed`)."""
    witting = policy._witting_labels()

    real_vetoes = {lbl for lbl in witting_vetoes if lbl in witting}
    if real_vetoes:
        raise WittingVeto(f"{len(real_vetoes)} witting guardian(s) vetoed recovery")

    real_approvals = {lbl for lbl in witting_approvals if lbl in witting}
    if len(real_approvals) < policy.min_witting_approvals:
        raise ApprovalsNotMet(
            f"need {policy.min_witting_approvals} witting approvals, got {len(real_approvals)}")

    if presented_shares and all(gs.guardian.institutional for gs in presented_shares):
        raise InstitutionalThresholdError(
            "presented shares are all institutional — a non-institutional party is required")

    custodian_shares = [CustodianShare(custodian=gs.guardian.custodian, share=gs.share)
                        for gs in presented_shares]
    return ts.unseal(sealed, user_half=user_half, custodian_shares=custodian_shares)
