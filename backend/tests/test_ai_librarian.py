"""Librarian retrieval + citation: surfaces authored works, quotes verbatim ONLY what's licensed."""

from atlas.ai.librarian import CorpusItem, is_open, librarian, retrieve
from atlas.ai.seam import StubModel

CORPUS = [
    CorpusItem(id=b"a", author="alice", title="Tidal photography guide", tags=("photo", "tide"),
               license="cc-by", price_atlas=0),                       # OPEN
    CorpusItem(id=b"b", author="bob", title="Advanced tide charts", tags=("tide", "charts"),
               license="content:quote", price_atlas=50),              # PAID
    CorpusItem(id=b"c", author="cara", title="Cooking with kelp", tags=("food", "kelp"),
               license="content:read", price_atlas=20),               # PAID, irrelevant to tide
    CorpusItem(id=b"d", author="dan", title="Regional tide law", tags=("tide", "law"),
               license="open", price_atlas=0, region="CA"),           # OPEN, region-scoped
]


def test_only_genuine_matches_surface():
    hits = retrieve("tide charts", CORPUS)
    ids = {h.item for h in hits}
    assert b"c" not in ids            # kelp/cooking has no overlap -> not surfaced (pull, not push)
    assert b"b" in ids and b"a" in ids


def test_relevance_ranking():
    hits = retrieve("tide charts", CORPUS)
    # "Advanced tide charts" overlaps both query tokens -> ranks above single-overlap items
    assert hits[0].item == b"b"


def test_open_work_is_licensed_free_but_still_attributed():
    hits = retrieve("tide", CORPUS)
    a = next(h for h in hits if h.item == b"a")
    assert a.licensed and not a.purchasable and a.author == "alice"


def test_paid_work_needs_purchase_until_bought():
    hits = retrieve("tide", CORPUS)
    b = next(h for h in hits if h.item == b"b")
    assert not b.licensed and b.purchasable            # surfaced for preview + buy
    hits2 = retrieve("tide", CORPUS, licensed_ids={b"b"})
    b2 = next(h for h in hits2 if h.item == b"b")
    assert b2.licensed and not b2.purchasable          # after purchase -> usable verbatim


def test_region_scoping():
    assert any(h.item == b"d" for h in retrieve("tide law", CORPUS, region="CA"))
    assert all(h.item != b"d" for h in retrieve("tide law", CORPUS, region="EU"))


def test_summary_quotes_only_licensed_subset():
    # Before buying bob's paid work: only the OPEN work (alice) feeds the model.
    res = librarian("tide charts and guides", CORPUS, StubModel())
    cited_authors = {s.author for s in res.inference.sources}
    assert "alice" in cited_authors and "bob" not in cited_authors
    assert {h.author for h in res.to_buy} == {"bob"}   # bob surfaced as buy-to-unlock

    # After buying bob's work: it becomes quotable and joins the grounded citations.
    res2 = librarian("tide charts and guides", CORPUS, StubModel(), licensed_ids={b"b"})
    assert "bob" in {s.author for s in res2.inference.sources}
    assert res2.to_buy == ()


def test_no_licensed_sources_means_no_inference():
    # A query matching only an unbought paid work -> nothing to quote -> no fabricated answer.
    res = librarian("kelp", CORPUS, StubModel())
    assert res.inference is None
    assert {h.author for h in res.to_buy} == {"cara"}


def test_is_open_helper():
    assert is_open("cc-by", 0) and is_open("AGPL-3.0", 0) and is_open("content:read", 0)  # free
    assert is_open("content:read", 0)                 # price 0 -> open regardless
    assert not is_open("content:quote", 50)           # paid content license
