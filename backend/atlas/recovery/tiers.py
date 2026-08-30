"""Recovery tiers (TRUST_LAYER.md #6) — the ladder from strongest/cheapest to last-resort.

  DEVICE_PRESENT (cryptographic) — you still hold a device / user-TSK half: unseal directly,
                                   no third party involved.
  SOCIAL         (guardianship)  — device lost, but your PRIVATE guardian set can reach the
                                   threshold (`recovery.guardianship`). Needs the ceremony half
                                   (name+password) too, so a guardian quorum alone is not enough.
  PHYSICAL_SELF  (in person)     — everything lost: name+password + a LIVE recovery person +
                                   the server threshold (`realid.recovery_anchor`).

INVARIANT — **never permanently locked out; the last credential is you.** PHYSICAL_SELF is the
FLOOR: reachable from what you carry in your own body and memory (your face, shown to an
accountable recovery person, + your name+password) with no device and no guardians. The System-ID
stays SECRET throughout — physical-self reconstructs you from the recovery pseudonym
(you-but-unlinkable), never from anything the system stored about you.

This module is SELECTION + POLICY: it decides which tier is reachable and picks the strongest.
Execution is delegated to the tier's owning module (see `TIER_OWNER`). Pure logic, no new crypto,
so no parity vectors — the Swift mirror reproduces the selection with native tests.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class RecoveryTierError(Exception):
    pass


class NoTierReachable(RecoveryTierError):
    """No recovery tier is reachable from the supplied factors — should be unreachable in
    practice, because PHYSICAL_SELF needs only (name+password) + a recovery person."""


class RecoveryTier(IntEnum):
    """Ordered by assurance/convenience — higher is stronger & cheaper. `select_tier` prefers
    the highest reachable."""

    PHYSICAL_SELF = 1   # the floor — always reachable by being you
    SOCIAL = 2
    DEVICE_PRESENT = 3  # highest


# Which module executes each tier (documented delegation, not imported here to keep this
# selection layer dependency-light).
TIER_OWNER = {
    RecoveryTier.DEVICE_PRESENT: "recovery.threshold_seal",     # unseal with your own shares/half
    RecoveryTier.SOCIAL: "recovery.guardianship",               # reconstruct_under_guardianship
    RecoveryTier.PHYSICAL_SELF: "realid.recovery_anchor",       # recover_total_loss
}


@dataclass(frozen=True)
class AvailableFactors:
    """What the user can currently supply. Each tier consumes a subset."""

    user_half: bool = False        # a device / user-TSK half in hand (DEVICE_PRESENT)
    guardian_quorum: bool = False  # can reach the guardianship threshold (SOCIAL)
    name_password: bool = False    # remembers name+password — the ceremony half (SOCIAL, PHYSICAL)
    recovery_person: bool = False  # can reach a live, accountable recovery person (PHYSICAL)
    recovery_card: bool = False    # holds the SE recovery card (only consumed when policy requires it)


@dataclass(frozen=True)
class RecoveryPolicy:
    """The user's recovery-authenticity choice. Defaults preserve the TRUST_LAYER.md #6 ladder.

    `require_card_for_social`: if True, the SOCIAL (guardianship) tier ALSO requires the SE
    recovery card — a guardian quorum + name/password alone will not recover you, so losing the
    card drops you to the in-person PHYSICAL_SELF floor. This is the user's authenticity-vs-
    recoverability trade-off. OFF (default): a guardian quorum can recover a lost-device user
    (more recoverable, matches the design of record). ON: guardian recovery still needs the
    hardware card, so seizing a card / coercing you at home is not enough and it does not water
    down authenticity. The guardians remain the off-site quorum either way; this adds the card
    as a required hardware factor. PHYSICAL_SELF (the never-locked-out floor) is unaffected.
    """

    require_card_for_social: bool = False


#: The default policy — the TRUST_LAYER.md #6 behaviour (no card required for the social tier).
DEFAULT_POLICY = RecoveryPolicy()


# What each tier REQUIRES, as a predicate over (AvailableFactors, RecoveryPolicy).
def _device_present(f: "AvailableFactors", policy: "RecoveryPolicy") -> bool:
    return f.user_half


def _social(f: "AvailableFactors", policy: "RecoveryPolicy") -> bool:
    # a guardian quorum plus the ceremony half (name+password) — a quorum alone cannot open it.
    # If the user's policy requires it, the SE recovery card is an additional required factor,
    # so a guardian quorum WITHOUT the card cannot reach this tier (it drops to physical-self).
    base = f.guardian_quorum and f.name_password
    if policy.require_card_for_social:
        return base and f.recovery_card
    return base


def _physical_self(f: "AvailableFactors", policy: "RecoveryPolicy") -> bool:
    # the floor: your memory (name+password) + your body shown to an accountable recovery person.
    # Never affected by policy — being yourself, in person, is always the last credential.
    return f.name_password and f.recovery_person


def reachable_tiers(factors: AvailableFactors,
                    policy: "RecoveryPolicy" = DEFAULT_POLICY) -> list[RecoveryTier]:
    """Every tier the supplied factors can satisfy under the user's policy, strongest first."""
    checks = {
        RecoveryTier.DEVICE_PRESENT: _device_present(factors, policy),
        RecoveryTier.SOCIAL: _social(factors, policy),
        RecoveryTier.PHYSICAL_SELF: _physical_self(factors, policy),
    }
    return sorted([tier for tier, ok in checks.items() if ok], reverse=True)


def select_tier(factors: AvailableFactors,
                policy: "RecoveryPolicy" = DEFAULT_POLICY) -> RecoveryTier:
    """The STRONGEST reachable tier under the user's policy. Raises `NoTierReachable` only if even
    the physical-self floor is unreachable (no name+password, or no recovery person)."""
    reachable = reachable_tiers(factors, policy)
    if not reachable:
        raise NoTierReachable(
            "no recovery tier reachable — the physical-self floor needs (name+password) + a "
            "live recovery person")
    return reachable[0]


def never_locked_out(factors: AvailableFactors) -> bool:
    """True iff the physical-self floor is reachable — i.e., the user can always get back in by
    being themselves. This is the guarantee the product makes, and it holds under ANY policy
    (the floor never requires a card)."""
    return _physical_self(factors, DEFAULT_POLICY)
