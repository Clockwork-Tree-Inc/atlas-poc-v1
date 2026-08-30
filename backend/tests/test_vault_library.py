"""Per-persona vault library + import (#29): a persona's shelf is its OWN isolated space (its vault),
imported content is sealed + fail-safe (reserved license, honest 'imported' provenance), and two
personas' libraries cannot see each other. Composes into a per-persona registry with the shared
global register."""

import os

from atlas.ai.librarian import ALL_RIGHTS_RESERVED, CorpusItem
from atlas.ai.library import InMemorySource, LibraryRegistry
from atlas.ai.vault_library import (
    VaultLibrarySource,
    import_bytes,
    read_content,
    shelf,
)
from atlas.session.vault import Vault


def _vault():
    return Vault(os.urandom(32))


def test_import_seals_content_and_shelves_it_fail_safe():
    v = _vault()
    item = import_bytes(v, id=b"doc1", author="me", title="Tide notes", content=b"the tide rises",
                        tags=["tide", "notes"])
    # fail-safe defaults: reserved license, honest imported provenance
    assert item.license == ALL_RIGHTS_RESERVED
    assert item.origin == "imported"
    # content is sealed in the vault, retrievable on demand
    assert read_content(v, item) == b"the tide rises"
    assert v.raw_at_rest("__atlas.library.content__/" + b"doc1".hex()) != b"the tide rises"  # encrypted
    # it appears on the persona's shelf
    assert [i.id for i in shelf(v)] == [b"doc1"]


def test_vault_source_surfaces_shelf_and_is_reserved_not_usable():
    v = _vault()
    import_bytes(v, id=b"doc1", author="me", title="Tide notes", content=b"x", tags=["tide"])
    reg = LibraryRegistry()
    reg.register(VaultLibrarySource("vault", v))
    hit = {h.hit.item: h for h in reg.search("tide")}[b"doc1"]
    assert hit.source == "vault"
    assert hit.hit.licensed is False          # reserved -> not usable/publishable-as-yours yet
    assert hit.hit.purchasable is False       # reserved + price 0 -> "ask", not for sale


def test_two_personas_libraries_are_isolated():
    a, b = _vault(), _vault()                 # different storage keys = separate spaces
    import_bytes(a, id=b"only-a", author="a", title="A tide", content=b"a", tags=["tide"])
    # persona B's shelf/source sees nothing of A's
    assert shelf(b) == []
    reg_b = LibraryRegistry()
    reg_b.register(VaultLibrarySource("vault", b))
    assert reg_b.search("tide") == []


def test_reimport_replaces_by_id():
    v = _vault()
    import_bytes(v, id=b"doc1", author="me", title="v1", content=b"one", tags=["tide"])
    import_bytes(v, id=b"doc1", author="me", title="v2", content=b"two", tags=["tide"])
    items = shelf(v)
    assert len(items) == 1 and items[0].title == "v2"
    assert read_content(v, items[0]) == b"two"


def test_per_persona_registry_composes_vault_plus_global_register():
    v = _vault()
    import_bytes(v, id=b"mine", author="me", title="My tide", content=b"x", tags=["tide"],
                 license="cc-by")             # I set a license I'm entitled to -> usable
    reg = LibraryRegistry()
    reg.register(VaultLibrarySource("vault", v))                 # this persona's private space
    reg.register(InMemorySource("register", [                    # the shared GLOBAL library
        CorpusItem(id=b"pub", author="someone", title="Public tide guide", tags=("tide",),
                   license="open"),
    ]))
    hits = {h.hit.item: h.source for h in reg.search("tide")}
    assert hits == {b"mine": "vault", b"pub": "register"}         # private + global, provenance kept
