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


# What each tier REQUIRES, as a predicate over AvailableFactors.
def _device_present(f: "AvailableFactors") -> bool:
    return f.user_half


def _social(f: "AvailableFactors") -> bool:
    # a guardian quorum plus the ceremony half (name+password) — a quorum alone cannot open it.
    return f.guardian_quorum and f.name_password


def _physical_self(f: "AvailableFactors") -> bool:
    # the floor: your memory (name+password) + your body shown to an accountable recovery person.
    return f.name_password and f.recovery_person


_REQUIREMENT = {
    RecoveryTier.DEVICE_PRESENT: _device_present,
    RecoveryTier.SOCIAL: _social,
    RecoveryTier.PHYSICAL_SELF: _physical_self,
}


def reachable_tiers(factors: AvailableFactors) -> list[RecoveryTier]:
    """Every tier the supplied factors can satisfy, strongest first."""
    reachable = [tier for tier, ok in _REQUIREMENT.items() if ok(factors)]
    return sorted(reachable, reverse=True)


def select_tier(factors: AvailableFactors) -> RecoveryTier:
    """The STRONGEST reachable tier. Raises `NoTierReachable` only if even the physical-self
    floor is unreachable (no name+password, or no recovery person)."""
    reachable = reachable_tiers(factors)
    if not reachable:
        raise NoTierReachable(
            "no recovery tier reachable — the physical-self floor needs (name+password) + a "
            "live recovery person")
    return reachable[0]


def never_locked_out(factors: AvailableFactors) -> bool:
    """True iff the physical-self floor is reachable — i.e., the user can always get back in by
    being themselves. This is the guarantee the product makes."""
    return _physical_self(factors)
