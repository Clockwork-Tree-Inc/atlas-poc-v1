"""AI seam + cryptographic provenance trail + author-citation economy: grounded inference,
capability-scoped agents, hash-chained/anchored trail, and pay-per-use to consenting authors."""
import pytest

from dataclasses import dataclass

from atlas.ai import (
    Agent,
    ModelNotEligible,
    ProvenanceTrail,
    Source,
    StubModel,
    admit,
    cite_and_reward,
    record_grant,
    record_inference,
    record_output,
    record_purchase,
    run_inference,
    web_search,
)
from atlas.economy import Coin
from atlas.ledger.backend import LocalBackend


# ---- seam: agent capabilities + grounded inference ----

def test_agent_scoped_access_grant_and_revoke():
    a = Agent(handle="ai:butler", owner="p:me")
    assert not a.can_access("space:family", now=0)
    a.grant("space:family", expires=100)
    assert a.can_access("space:family", now=10)
    assert not a.can_access("space:family", now=200)   # expired
    a.grant("space:family", expires=100)
    a.revoke("space:family")
    assert not a.can_access("space:family", now=10)     # revoked


def test_grounded_inference_uses_only_licensed_sources_and_attaches_them():
    model = StubModel()
    retrieval = [
        Source(item=b"book-1", author="author:asha", license_ok=True),
        Source(item=b"book-2", author="author:ben", license_ok=False),   # not licensed -> excluded
    ]
    r = run_inference(model, "what is X?", retrieval)
    assert r.model_hash == model.weights_hash
    assert [s.author for s in r.sources] == ["author:asha"]   # grounded: only the licensed one
    assert "author:asha" in r.output


# ---- trail: hash-chain + verify + anchor ----

def test_trail_is_hash_chained_and_tamper_evident():
    t = ProvenanceTrail()
    record_grant(t, owner="p:me", agent="ai:butler", scope="space:family", expires=100)
    record_purchase(t, buyer="p:me", item=b"book-1", license_terms="personal-use;ai-context-ok")
    assert t.verify_chain()
    t._events[0] = t._events[0].__class__(kind="grant", actor="p:attacker",
                                          payload=t._events[0].payload, prev=t._events[0].prev)
    assert not t.verify_chain()                          # tamper breaks the chain


def test_trail_head_anchors_to_the_ledger():
    t = ProvenanceTrail()
    record_grant(t, owner="p:me", agent="ai:butler", scope="s", expires=1)
    b = LocalBackend()
    t.anchor(b, owner_id=b"atlas/ai-trail", epoch_round=(1).to_bytes(8, "big"))
    assert b.latest(b"atlas/ai-trail") == t.head()       # immutable checkpoint of the trail


# ---- author-citation economy ----

def test_every_source_cited_and_consenting_authors_paid():
    coin = Coin()
    coin._mint("p:reader", 1_000)                        # the reader/payer has earned coin
    model = StubModel()
    r = run_inference(model, "q", [
        Source(b"book-1", "author:asha", True),          # consenting -> paid
        Source(b"book-2", "author:ben", True),           # cited but not reward-eligible
    ])
    t = ProvenanceTrail()
    cites = cite_and_reward(t, coin, r, payer="p:reader", per_use_fee=50,
                            rewardable=frozenset({"author:asha"}))
    # EVERY source is attributed (always cite)
    assert {c.author for c in cites} == {"author:asha", "author:ben"}
    assert len(t.events("citation")) == 2
    # consenting author paid; non-eligible author cited but not paid
    assert coin.balance("author:asha") == 50 and coin.balance("author:ben") == 0
    assert coin.balance("p:reader") == 950
    assert [c.paid for c in cites if c.author == "author:asha"] == [50]


# ---- end to end: grant -> purchase -> infer -> cite+reward -> anchor -> verify ----

def test_end_to_end_ai_content_rights_trail():
    coin = Coin()
    coin._mint("p:me", 1_000)
    t = ProvenanceTrail()
    agent = Agent("ai:butler", "p:me")

    agent.grant("space:study", expires=100)
    record_grant(t, owner="p:me", agent=agent.handle, scope="space:study", expires=100)
    record_purchase(t, buyer="p:me", item=b"phys-textbook",
                    license_terms="personal-use;ai-context-ok;no-resale")

    result = run_inference(StubModel(), "explain entropy",
                           [Source(b"phys-textbook", "author:carnot", True)])
    record_inference(t, invoker=agent.handle, result=result)
    record_output(t, invoker=agent.handle, result=result)
    cite_and_reward(t, coin, result, payer="p:me", per_use_fee=10,
                    rewardable=frozenset({"author:carnot"}))

    b = LocalBackend()
    t.anchor(b, owner_id=b"atlas/ai-trail", epoch_round=(1).to_bytes(8, "big"))

    assert t.verify_chain()                              # full lineage intact + tamper-evident
    assert b.latest(b"atlas/ai-trail") == t.head()       # anchored
    assert coin.balance("author:carnot") == 10           # author earned a citation micropayment
    kinds = [e.kind for e in t.events()]
    assert kinds == ["grant", "purchase", "inference", "output", "citation"]


# ---- open-only hard rule: closed/vendor and open-but-scraped models are refused ----

@dataclass
class _ClosedVendorModel:
    @property
    def weights_hash(self): return b"vendor-closed"
    @property
    def open_weights(self): return False
    @property
    def ethically_sourced(self): return False
    def generate(self, prompt, context): return "should never run"


@dataclass
class _OpenButScrapedModel:
    @property
    def weights_hash(self): return b"open-but-scraped"
    @property
    def open_weights(self): return True
    @property
    def ethically_sourced(self): return False
    def generate(self, prompt, context): return "should never run"


def test_closed_vendor_model_is_refused():
    with pytest.raises(ModelNotEligible):
        admit(_ClosedVendorModel())
    with pytest.raises(ModelNotEligible):
        run_inference(_ClosedVendorModel(), "q", [])          # refused before it can generate


def test_open_but_not_ethically_sourced_is_refused():
    with pytest.raises(ModelNotEligible):
        run_inference(_OpenButScrapedModel(), "q", [])        # open weights alone isn't enough


# ---- internet search as a tool: web sources are grounded-cited ----

def test_web_search_results_are_cited_attribution_always_payment_only_if_opted_in():
    coin = Coin()
    coin._mint("p:reader", 1_000)
    web = web_search("best kombucha", [
        (b"https://foodsite.example/a", "site:foodsite"),     # not an Atlas participant
        (b"https://blog.example/b", "author:asha"),           # opted-in Atlas author
    ])
    r = run_inference(StubModel(), "best kombucha", web)
    assert [s.author for s in r.sources] == ["site:foodsite", "author:asha"]   # web sources grounded
    t = ProvenanceTrail()
    cite_and_reward(t, coin, r, payer="p:reader", per_use_fee=5,
                    rewardable=frozenset({"author:asha"}))
    assert len(t.events("citation")) == 2                     # every web source cited (attribution)
    assert coin.balance("author:asha") == 5                   # opted-in web author paid
    assert coin.balance("site:foodsite") == 0                 # non-participant cited, not paid
