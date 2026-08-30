"""Agent authority — the ONE enforcement point that composes the leash and the gate. Closes the gap
where `agent_delegation` and `supply_gate` were each correct but never checked against each other.

`principal_class` inside a delegation is SELF-DECLARED, so on its own an agent key could mint itself a
root delegation claiming to be an INDIVIDUAL and no code would notice. This function is the only
sanctioned way to ask "may this agent, via its delegation chain, perform this action?" — and it
cross-checks the chain's root principal against a REAL credential:

  1. the delegation chain is valid (roots at a non-agent, attenuating, all signatures verify);
  2. the supplied root profile IS the chain's root principal (same key) and agrees on class;
  3. the agent's leaf actually grants the capability in scope;
  4. the ROOT PRINCIPAL itself passes the Real-ID supply gate for the action (real-id, + registration
     for an organization). This is what makes the self-declared class REAL — verification-not-authority.

So an agent cannot borrow authority it can't ground in a credentialed human/organization.
Reference of record. Swift parity: ios/AtlasCore/Sources/AtlasCore/Participant/AgentAuthority.swift.
"""
from __future__ import annotations

from typing import Optional, Sequence, Set

from .agent_delegation import Delegation, authorized, root_principal, verify_chain
from .economy.supply_gate import can_perform
from .participant import Profile


def agent_may_supply(chain: Sequence[Delegation], *, action: str, scope: bytes, now: int,
                     root_profile: Profile, capability: Optional[str] = None,
                     trusted_verifier_keys: Set[bytes] = frozenset(),
                     trusted_registry_keys: Set[bytes] = frozenset()) -> bool:
    """May the leashed agent perform `action` in `scope` right now? True iff the chain is valid, the
    root profile IS the chain's credentialed root principal, the agent's leaf grants the capability,
    AND the root passes the Real-ID supply gate. `capability` defaults to `action`."""
    if not verify_chain(chain, now=now):
        return False

    root_pub, root_class = root_principal(chain)
    # the supplied profile must BE the chain's root principal — same key, same declared class.
    if root_profile.public.encode() != root_pub.encode():
        return False
    if root_profile.entity_class is not root_class:
        return False

    # the agent's leaf must actually grant this capability in a covering scope.
    if not authorized(chain, capability=(capability or action), scope=scope, now=now):
        return False

    # THE CROSS-CHECK: the root principal must itself hold the real credential for a supply action —
    # an agent can't self-declare being an individual; the human/org behind it must actually pass.
    return can_perform(root_profile, action, trusted_verifier_keys=trusted_verifier_keys,
                       trusted_registry_keys=trusted_registry_keys)
