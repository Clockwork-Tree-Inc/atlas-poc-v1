"""Federated library registry (#26): plug in many LibrarySources, rank globally, tag provenance,
and enforce license-by-default — an item with no/unknown license is all-rights-reserved (fail-safe),
never accidentally free, even at price 0."""

from atlas.ai.librarian import ALL_RIGHTS_RESERVED, CorpusItem, is_open
from atlas.ai.library import (
    InMemorySource,
    LibraryRegistry,
    normalize_license,
)
from atlas.ai.seam import StubModel


def _vault():
    return InMemorySource("vault", [
        CorpusItem(id=b"v1", author="me", title="My tide notes", tags=("tide", "notes"),
                   license="cc-by", price_atlas=0),                       # OPEN
    ])


def _auracles():
    return InMemorySource("auracles", [
        CorpusItem(id=b"a1", author="imogen", title="Tide song", tags=("tide", "music"),
                   license="content:quote", price_atlas=40),              # PAID
        CorpusItem(id=b"a2", author="anon", title="Unmarked tide loop", tags=("tide", "loop"),
                   license="", price_atlas=0),                            # NO LICENSE -> fail-safe
    ])


def test_normalize_license_is_fail_safe():
    assert normalize_license(CorpusItem(id=b"x", author="a", title="t", tags=(), license="")).license \
        == ALL_RIGHTS_RESERVED
    assert normalize_license(CorpusItem(id=b"x", author="a", title="t", tags=(), license="unknown")).license \
        == ALL_RIGHTS_RESERVED
    assert normalize_license(CorpusItem(id=b"x", author="a", title="t", tags=(), license="CC-BY")).license \
        == "cc-by"                                                        # explicit kept (lower-cased)


def test_reserved_is_not_open_even_at_price_zero():
    assert is_open(ALL_RIGHTS_RESERVED, 0) is False                       # the whole point of #26
    assert is_open("", 0) is False
    assert is_open("cc-by", 0) is True                                    # real open still open


def test_registry_aggregates_sources_with_provenance():
    reg = LibraryRegistry()
    reg.register(_vault())
    reg.register(_auracles())
    assert reg.sources == ("vault", "auracles")
    hits = reg.search("tide")
    by_id = {h.hit.item: h for h in hits}
    assert set(by_id) == {b"v1", b"a1", b"a2"}                            # all three tide works
    assert by_id[b"v1"].source == "vault"
    assert by_id[b"a1"].source == "auracles"


def test_license_by_default_marks_unlicensed_work_not_usable():
    reg = LibraryRegistry()
    reg.register(_auracles())
    hits = {h.hit.item: h.hit for h in reg.search("tide")}
    # The unmarked work (a2): fail-safe -> reserved, NOT licensed, and NOT for sale (price 0) ->
    # surfaced as "ask", never auto-free and never fed to the model.
    assert hits[b"a2"].license == ALL_RIGHTS_RESERVED
    assert hits[b"a2"].licensed is False
    assert hits[b"a2"].purchasable is False
    # The paid work (a1): not licensed until bought, but purchasable.
    assert hits[b"a1"].licensed is False and hits[b"a1"].purchasable is True


def test_first_source_wins_on_duplicate_id():
    s1 = InMemorySource("first", [CorpusItem(id=b"dup", author="x", title="tide A", tags=("tide",),
                                             license="cc-by")])
    s2 = InMemorySource("second", [CorpusItem(id=b"dup", author="y", title="tide B", tags=("tide",),
                                              license="content:quote", price_atlas=99)])
    reg = LibraryRegistry()
    reg.register(s1)
    reg.register(s2)
    corpus, origin = reg.gather("tide")
    assert origin[b"dup"] == "first"                                      # stable provenance
    assert {c.id: c.license for c in corpus}[b"dup"] == "cc-by"           # first source's license


def test_answer_quotes_only_licensed_subset_across_sources():
    reg = LibraryRegistry()
    reg.register(_vault())        # v1 open
    reg.register(_auracles())     # a1 paid (not held), a2 reserved
    res = reg.answer("tide", StubModel())
    cited_ids = {h.item for h in res.cited}
    assert cited_ids == {b"v1"}                                           # only the open work is quoted
    assert res.inference is not None
    # After buying a1, it joins the cited subset; a2 (reserved) never does.
    res2 = reg.answer("tide", StubModel(), licensed_ids={b"a1"})
    assert {h.item for h in res2.cited} == {b"v1", b"a1"}
