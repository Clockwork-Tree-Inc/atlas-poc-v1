"""Supply-side Real-ID gate — the regulated boundary of the economy.

The rule: the SUPPLY side is accountable, the DEMAND side is free.
  * DEMAND (buy / browse / consume) — anonymous is fine. No credential required.
  * SUPPLY (sell / list / earn / provide / own an org / receive payment) — requires a Real-ID:
    the acting profile must hold a valid `real-id` attestation from a verifier KEY the checker
    trusts. An ORGANIZATION additionally needs a `registered` attestation from a trusted registry.

This is where obligation actually sits (sellers/earners owe duties — tax, consumer protection, AML;
buyers mostly don't), so gating earn/sell with Real-ID is the compliance hook in the right spot.

Real-ID ≠ doxxed: this checks that the profile HOLDS the credential (via `participant.presents`),
NOT that it has gone public — accountability is resolvable, identity isn't broadcast. Verification-
not-authority: trust binds to the verifier/registry KEY SET the checker supplies; Atlas anoints no
root. An AGENT is never a direct supply actor — it acts under a delegation whose root principal must
itself pass this gate (see `agent_delegation`).

Assembly only — composes `participant.presents` + `EntityClass`. No new crypto.
"""
from __future__ import annotations

from typing import Set

from ..marketplace import EntityClass
from ..participant import Profile, presents

REAL_ID_CLAIM = "real-id"
REGISTRATION_CLAIM = "registered"

DEMAND_ACTIONS = frozenset({"buy", "browse", "consume", "read_review"})
SUPPLY_ACTIONS = frozenset({"sell", "list", "earn", "provide", "own_org", "receive_payment"})


class SupplyGateError(Exception):
    pass


def has_real_id(profile: Profile, *, trusted_verifier_keys: Set[bytes]) -> bool:
    return presents(profile, claim=REAL_ID_CLAIM, trusted_authority_keys=trusted_verifier_keys)


def has_registration(profile: Profile, *, trusted_registry_keys: Set[bytes]) -> bool:
    return presents(profile, claim=REGISTRATION_CLAIM, trusted_authority_keys=trusted_registry_keys)


def is_supply(action: str) -> bool:
    return action in SUPPLY_ACTIONS


def can_perform(profile: Profile, action: str, *, trusted_verifier_keys: Set[bytes] = frozenset(),
                trusted_registry_keys: Set[bytes] = frozenset()) -> bool:
    """May this profile perform `action`? Demand is always allowed (anonymous OK). Supply requires a
    trusted Real-ID; an organization also needs a trusted registration; an agent is never a direct
    supply actor (it must act via a delegation whose root principal is gated instead)."""
    if action in DEMAND_ACTIONS:
        return True
    if action not in SUPPLY_ACTIONS:
        raise SupplyGateError(f"unknown action {action!r}")

    if profile.entity_class is EntityClass.AGENT:
        return False                                    # agents act via delegation, not directly
    if not has_real_id(profile, trusted_verifier_keys=trusted_verifier_keys):
        return False                                    # earners/sellers must be Real-ID accountable
    if profile.entity_class.is_organization and not has_registration(
            profile, trusted_registry_keys=trusted_registry_keys):
        return False                                    # an org must also be registered to operate
    return True
