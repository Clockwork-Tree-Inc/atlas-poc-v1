"""Talk-to-AI grounded chat (#21): capability-scoped, multi-turn, grounded citation over the
federated registry, open-model-only. Reserved/unlicensed works are never fed to the model."""

import pytest

from atlas.ai.chat import AgentCapabilityError, LibrarianAgent
from atlas.ai.librarian import CorpusItem
from atlas.ai.library import InMemorySource, LibraryRegistry
from atlas.ai.seam import Agent, ModelNotEligible, StubModel


def _registry():
    reg = LibraryRegistry()
    reg.register(InMemorySource("vault", [
        CorpusItem(id=b"v1", author="me", title="My tide notes", tags=("tide",), license="cc-by"),
    ]))
    reg.register(InMemorySource("auracles", [
        CorpusItem(id=b"a1", author="imogen", title="Tide song", tags=("tide",),
                   license="content:quote", price_atlas=40),          # paid, not held
        CorpusItem(id=b"a2", author="anon", title="Unmarked tide loop", tags=("tide",),
                   license=""),                                        # reserved by default
    ]))
    return reg


def _granted_agent(now=0):
    a = Agent(handle="lib-agent", owner="me")
    a.grant("vault", expires=100)
    return a


class _ClosedModel(StubModel):
    @property
    def open_weights(self) -> bool:
        return False


def test_grounded_answer_cites_only_licensed_subset():
    chat = LibrarianAgent(agent=_granted_agent(), registry=_registry(), model=StubModel())
    turn = chat.ask("tide", now=0)
    cited = {h.item for h in turn.result.cited}
    assert cited == {b"v1"}                          # open work only; paid + reserved not fed in
    assert "me" in turn.answer                       # grounded citation shows in the stub output
    assert turn.result.to_buy                        # the paid work is surfaced to purchase


def test_buying_unlocks_a_source_next_turn():
    chat = LibrarianAgent(agent=_granted_agent(), registry=_registry(), model=StubModel())
    turn = chat.ask("tide", now=0, licensed_ids={b"a1"})
    assert {h.item for h in turn.result.cited} == {b"v1", b"a1"}   # a2 (reserved) still excluded


def test_capability_required_and_revocable():
    a = Agent(handle="lib-agent", owner="me")        # no grant yet
    chat = LibrarianAgent(agent=a, registry=_registry(), model=StubModel())
    with pytest.raises(AgentCapabilityError):
        chat.ask("tide", now=0)
    a.grant("vault", expires=100)
    assert chat.ask("tide", now=0).result.cited      # now allowed
    with pytest.raises(AgentCapabilityError):        # ... but the grant has expired by now=200
        chat.ask("tide", now=200)


def test_closed_vendor_model_is_refused():
    chat = LibrarianAgent(agent=_granted_agent(), registry=_registry(), model=_ClosedModel())
    with pytest.raises(ModelNotEligible):            # open weights only — enforced through the seam
        chat.ask("tide", now=0)


def test_transcript_accumulates_multi_turn():
    chat = LibrarianAgent(agent=_granted_agent(), registry=_registry(), model=StubModel())
    chat.ask("tide", now=0)
    chat.ask("kelp", now=1)
    assert [t.query for t in chat.transcript] == ["tide", "kelp"]


def test_group_authority_owner_grants_participants_use():
    owner = b"owner-handle"
    friend = b"friend-handle"
    stranger = b"stranger-handle"
    chat = LibrarianAgent(agent=_granted_agent(), registry=_registry(), model=StubModel(),
                          owner_handle=owner)
    # owner always may invoke; an ungranted participant is refused
    assert chat.ask("tide", now=0, invoker=owner).invoker == owner
    with pytest.raises(AgentCapabilityError):
        chat.ask("tide", now=0, invoker=stranger)
    # grant a chat/space participant use -> they can invoke; the turn RECORDS who asked
    chat.allow_invoker(friend)
    t = chat.ask("tide", now=0, invoker=friend)
    assert t.invoker == friend                              # provenance: who invoked
    # revocation is immediate
    chat.revoke_invoker(friend)
    with pytest.raises(AgentCapabilityError):
        chat.ask("tide", now=0, invoker=friend)
    # invokers borrow USE, never authority: the agent's scope grant still gates everything
    chat.allow_invoker(friend)
    with pytest.raises(AgentCapabilityError):
        chat.ask("tide", now=200, invoker=friend)           # owner's scope grant expired -> refused
