"""Agent delegation — the cryptographic LEASH that makes an AI agent a safe first-class participant.

An agent is never a root actor. It acts only under a DELEGATION signed by a principal, scoped to a
set of capabilities + a space, and expiring at an epoch. A principal may be an individual or a
business — or, for SUB-DELEGATION, a parent agent — but a chain of delegations must always terminate
at a non-agent root. So "who did this?" always resolves to a responsible human/business, and there
is no autonomous authority with no one behind it (the human-rooted-forest invariant, in the small).

Two invariants enforced here:
  * ROOTED — a chain's first link is granted by a principal that `can_be_principal` (individual /
    business) with no parent; every later link is granted by the agent the previous link leashed.
  * ATTENUATING — a sub-delegation can only NARROW authority: its capabilities ⊆ the parent's, its
    scope is the same or narrower, and it expires no later than the parent.

Not new crypto — HybridSig over a domain-separated, length-prefixed body + a hash-linked chain.
Composes with `spaces.space_policy` (an agent's role in a space) — the delegation says WHAT an agent
may do; the space policy says WHERE, and both are logged.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import List, Sequence, Tuple

from .crypto.primitives import H
from .crypto.sign import HybridSigKeypair, HybridSigPublic, sign, verify
from .marketplace import EntityClass

_DELEG = b"atlas/agent-delegation/v1"
_DELEG_ID = b"atlas/agent-delegation-id/v1"


class DelegationError(Exception):
    pass


def _lp(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


@dataclass(frozen=True)
class Delegation:
    """One leash link: `principal` grants `agent` `capabilities` within `scope` until `not_after`.
    `parent` is the id of the parent delegation for a sub-delegation, else b"" for a root link."""
    principal: HybridSigPublic
    principal_class: EntityClass
    agent: HybridSigPublic
    capabilities: Tuple[str, ...]
    scope: bytes                       # a space_id, or b"" for global
    not_after: int                     # expiry epoch (inclusive)
    parent: bytes = b""                # parent delegation id, or b"" if rooted at the principal
    sig: bytes = b""

    def body(self) -> bytes:
        caps = sorted(set(self.capabilities))
        parts = [_DELEG, _lp(self.principal.encode()), _lp(self.principal_class.value.encode()),
                 _lp(self.agent.encode()), len(caps).to_bytes(4, "big")]
        parts.extend(_lp(c.encode()) for c in caps)
        parts.extend([_lp(self.scope), self.not_after.to_bytes(8, "big"), _lp(self.parent)])
        return b"".join(parts)

    def id(self) -> bytes:
        return H(_DELEG_ID, self.body())


def delegate(principal_kp: HybridSigKeypair, *, principal_class: EntityClass,
             agent: HybridSigPublic, capabilities: Sequence[str], scope: bytes, not_after: int,
             parent: bytes = b"") -> Delegation:
    """Issue a leash. `principal_class` records what the granter is (individual/business/agent)."""
    d = Delegation(principal=principal_kp.public, principal_class=principal_class, agent=agent,
                   capabilities=tuple(capabilities), scope=scope, not_after=not_after, parent=parent)
    return replace(d, sig=sign(principal_kp, d.body()))


def verify_link(d: Delegation, *, now: int) -> bool:
    """A single link is well-formed: signature valid, not expired, and a ROOT link is granted by a
    principal that may root authority (individual/business, no parent). Sub-delegation links (parent
    set) may be granted by an agent — the chain check enforces they descend from a real root."""
    if not verify(d.principal, d.body(), d.sig):
        return False
    if now > d.not_after:
        return False
    if not d.parent:                                  # a root link must be from a non-agent principal
        return d.principal_class.can_be_principal
    return True


def verify_chain(chain: Sequence[Delegation], *, now: int) -> bool:
    """A chain is valid iff it roots at a non-agent, each link descends from the previous (the
    sub-delegator was the previously-leashed agent), authority only NARROWS, and none has expired."""
    if not chain:
        return False
    root = chain[0]
    if root.parent or not root.principal_class.can_be_principal:
        return False
    for i, d in enumerate(chain):
        if not verify_link(d, now=now):
            return False
        if i == 0:
            continue
        prev = chain[i - 1]
        if d.parent != prev.id():                                    # links to the exact parent
            return False
        if d.principal.encode() != prev.agent.encode():              # sub-delegator = prior agent
            return False
        if not set(d.capabilities) <= set(prev.capabilities):        # attenuation: caps ⊆ parent
            return False
        if not _scope_within(d.scope, prev.scope):                   # scope same or narrower
            return False
        if d.not_after > prev.not_after:                             # expires no later than parent
            return False
    return True


def _scope_within(child: bytes, parent: bytes) -> bool:
    """Global parent (b"") contains any scope; otherwise scopes must match exactly (no partial
    space hierarchy here — a narrower model can extend this)."""
    return parent == b"" or child == parent


def authorized(chain: Sequence[Delegation], *, capability: str, scope: bytes, now: int) -> bool:
    """The question the enforcer asks: may the leashed agent do `capability` in `scope` right now?
    True iff the chain is valid AND the final link grants that capability in a covering scope."""
    if not verify_chain(chain, now=now):
        return False
    leaf = chain[-1]
    return capability in leaf.capabilities and _scope_within(scope, leaf.scope)


def root_principal(chain: Sequence[Delegation]) -> Tuple[HybridSigPublic, EntityClass]:
    """The responsible party a chain resolves to — always a human or business."""
    if not chain:
        raise DelegationError("empty chain has no root")
    return chain[0].principal, chain[0].principal_class
