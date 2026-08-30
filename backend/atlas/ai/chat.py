"""Talk-to-AI — a grounded, capability-scoped, multi-turn librarian chat.

The chat agent is a human-rooted, revocable principal (seam.Agent) that answers over the persona's
own shelves + the federated register (library.LibraryRegistry), through an OPEN, ethically-sourced
model (seam.admit). Three properties hold on every turn:

  GROUNDED. The citations are what actually fed the model — attached by the system, not self-
  reported — and reserved/unlicensed works are surfaced-to-buy, never fed in (library + librarian).

  CAPABILITY-SCOPED. The agent must currently HOLD a live grant for the corpus scope; a missing or
  expired capability refuses the turn. Revoking the grant stops the agent mid-conversation.

  LOCAL-FIRST + OPEN. The Model is a protocol: a real on-device / node open model (OLMo/Pleias)
  drops in unchanged; the reference StubModel is deterministic. Closed/vendor models are refused.
  The phone does retrieval+citation on-device; generation runs at the node/server tier behind this
  same seam — no central mega-GPU, no vendor lock.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple

from .librarian import LibrarianResult
from .library import LibraryRegistry
from .seam import Agent, Model


class AgentCapabilityError(PermissionError):
    """The agent does not currently hold a live capability for the corpus it was asked to read."""


@dataclass(frozen=True)
class Turn:
    """One exchange: the query, WHO asked it (provenance — the invoker is recorded on every
    turn), and the grounded, cited result."""
    query: str
    result: LibrarianResult
    invoker: bytes = b""

    @property
    def answer(self) -> str:
        return self.result.inference.output if self.result.inference else ""


@dataclass
class LibrarianAgent:
    """A talk-to-AI session bound to one human-rooted agent, one federated corpus, and one open
    model. Multi-turn: each ask appends to the transcript."""
    agent: Agent
    registry: LibraryRegistry
    model: Model
    scope: str = "vault"                 # the capability the agent must hold to read the corpus
    owner_handle: bytes = b""            # the human the agent acts for — may always invoke
    _invokers: Set[bytes] = field(default_factory=set)   # participants GRANTED use of this agent
    _transcript: List[Turn] = field(default_factory=list)

    # -- group authority: the owner grants chat/space participants use of the agent -----------
    # The AI is a grantable capability like any other: participants the owner allows may invoke
    # it; every turn records WHO invoked (provenance), and revocation is immediate. The agent
    # still acts under the OWNER's authority/scopes — invokers borrow use, never authority.

    def allow_invoker(self, participant: bytes) -> None:
        self._invokers.add(participant)

    def revoke_invoker(self, participant: bytes) -> None:
        self._invokers.discard(participant)

    def may_invoke(self, participant: bytes) -> bool:
        return participant == self.owner_handle or participant in self._invokers

    def ask(self, query: str, *, now: int, invoker: Optional[bytes] = None,
            licensed_ids: Optional[Set[bytes]] = None,
            region: Optional[str] = None, top_k: int = 10) -> Turn:
        """Answer one turn. Refuses unless (a) the INVOKER is the owner or was granted use —
        so the agent never answers instructions from an ungranted participant/source — and (b)
        the agent holds a LIVE grant for `scope` (revoke or expiry stops it mid-conversation).
        The answer quotes only the licensed subset; the model is admitted (open + ethically-
        sourced) inside the registry/librarian path."""
        who = invoker if invoker is not None else self.owner_handle
        if not self.may_invoke(who):
            raise AgentCapabilityError(
                f"participant {who!r} was not granted use of agent {self.agent.handle!r}"
            )
        if not self.agent.can_access(self.scope, now=now):
            raise AgentCapabilityError(
                f"agent {self.agent.handle!r} lacks a live '{self.scope}' capability"
            )
        result = self.registry.answer(query, self.model, region=region, top_k=top_k,
                                      licensed_ids=licensed_ids)
        turn = Turn(query=query, result=result, invoker=who)
        self._transcript.append(turn)
        return turn

    @property
    def transcript(self) -> Tuple[Turn, ...]:
        return tuple(self._transcript)
