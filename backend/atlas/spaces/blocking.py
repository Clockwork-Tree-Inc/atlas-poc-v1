"""Space/conversation identity policy + person-scoped blocking, enforced by a ZERO-KNOWLEDGE
person-tag — the host never sees the root.

A conversation IS a space (a small one). The SPACE CREATOR sets the identity policy. To act in a
non-OPEN space, a participant PRESENTS a `PersonTagProof` for the space's SCOPE: a verified
nullifier `N` bound in zero-knowledge to the hidden root a verified-human credential certifies
(`zk/person_tag.py`). The host verifies the proof and keys one-person-one-account + blocking on
`N` — never the root. (This replaces the old raw-root path that leaked the master root to the host.)

BLOCK SCOPES — both are "just a scope":
  * per-space        — scope = space_id; block from THIS space only (unlinkable across spaces).
  * personal-global  — scope = the AUTHORITY DOMAIN id; spaces under one authority share that scope
                       and a shared blocklist, so a block applies across ALL spaces that authority
                       governs — and nowhere else (never another authority's spaces; a network-wide
                       ban is a governance action, not this).
"""
from __future__ import annotations

from enum import Enum
from typing import Optional, Set

from ..zk.person_tag import PersonTagProof, verify_person_tag


class IdentityPolicy(Enum):
    """Set by the space creator. You cannot have full anonymity AND one-person-one-account at once
    — enforcing uniqueness needs a person-tag. So:

      * OPEN            — no person-tag: fully anonymous, but a human CAN hold MULTIPLE accounts
                          (Sybil-OPEN by design). ONLY for Sybil-insensitive spaces; never the
                          default; never where anything is counted.
      * VERIFIED_HUMAN  — RECOMMENDED DEFAULT: present a scope-bound person-tag proof -> ANONYMOUS
                          *and* one-person-one-account (uniqueness without revealing who).
      * IDENTIFIED      — additionally present a Real-ID / verified-org credential (caller-ID).

    Sybil-sensitive actions (votes/reviews/polls/UBI) dedupe on the PERSON-tag, not the persona.
    """
    OPEN = "open"
    VERIFIED_HUMAN = "verified_human"
    IDENTIFIED = "identified"


class AuthorityDomain:
    """A blocker's authority domain: (a) a SHARED personal-global blocklist for spaces that use this
    domain's scope, and (b) declared, revocable AI-agent delegations. Only the authority holds it;
    in production, mutating it is gated by an owner/mod Authority grant."""

    def __init__(self, authority_id: bytes):
        self.authority_id = authority_id
        self._blocked: Set[int] = set()      # person-tags (nullifiers N) blocked across this domain
        self._agents: Set[bytes] = set()

    def block(self, tag: int) -> None:
        self._blocked.add(tag)

    def is_blocked(self, tag: int) -> bool:
        return tag in self._blocked

    # -- declared AI agents (butler / lab assistant): human-rooted, bounded, revocable --
    def delegate_agent(self, agent_id: bytes) -> None:
        self._agents.add(agent_id)

    def revoke_agent(self, agent_id: bytes) -> None:
        self._agents.discard(agent_id)

    def agent_allowed(self, agent_id: bytes) -> bool:
        return agent_id in self._agents


class Space:
    """A space (a conversation is a small one). `scope` is the person-tag scope: the space_id for
    per-space blocking, or an AuthorityDomain's id for spaces that participate in personal-global
    blocking. The creator sets the identity policy and holds the per-space blocklist."""

    def __init__(self, scope: bytes, policy: IdentityPolicy, domain: Optional[AuthorityDomain] = None):
        self.scope = scope
        self.policy = policy
        self.domain = domain
        self._blocked: Set[int] = set()      # per-space blocked person-tags (nullifiers N)

    def block(self, tag: int) -> None:
        """Per-space block of a person-tag N (the authority learns N when the person presents)."""
        self._blocked.add(tag)

    def admit(self, proof: Optional[PersonTagProof], *, epoch: int, nonce: bytes,
              identified: bool = False) -> bool:
        """Admit a participant. OPEN: anyone (anonymous), no proof, no person-blocking. Otherwise the
        participant must present a `PersonTagProof` for THIS scope: it must verify (ZK binding to a
        credentialed root + freshness), satisfy the policy, and its `N` must not be blocked
        (per-space, or personal-global if this space uses its authority domain's scope). The root is
        never seen — the host only ever learns the nullifier `N`."""
        if self.policy is IdentityPolicy.OPEN:
            return True                                   # anonymous ok; no person-tag, no blocking
        if proof is None:
            return False                                  # policy REQUIRES a presented person-tag
        if proof.scope != self.scope:
            return False                                  # the tag must be for THIS space's scope
        if not verify_person_tag(proof, expected_epoch=epoch, expected_nonce=nonce):
            return False                                  # ZK binding + freshness (no replay; root unseen)
        if self.policy is IdentityPolicy.IDENTIFIED and not identified:
            return False                                  # caller-ID: also need a Real-ID / verified-org credential
        if proof.N in self._blocked:
            return False                                  # per-space block
        if (self.domain is not None and self.scope == self.domain.authority_id
                and self.domain.is_blocked(proof.N)):
            return False                                  # personal-global block (domain-scoped spaces)
        return True

    def admit_agent(self, agent_id: bytes) -> bool:
        """Admit a DECLARED AI agent (butler / lab assistant) — NOT as a human peer, but in the
        agent lane — iff this space's authority has delegated it (bounded, revocable). Clause W:
        agents act through declared, human-rooted proxies, never as indistinguishable humans."""
        return self.domain is not None and self.domain.agent_allowed(agent_id)
