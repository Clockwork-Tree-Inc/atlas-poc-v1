"""Publish to the global library (#28): copy a persona's shelf item into the ONE shared register,
under the persona's handle, signed — content stays in the vault; author picks the license; entries
are unlinkable to System-ID; only the handle's controller can publish/unpublish as it."""

import os

import pytest

from atlas.ai.librarian import ALL_RIGHTS_RESERVED
from atlas.ai.library import LibraryRegistry
from atlas.ai.publish import (
    FederatedRegister,
    PublishError,
    make_entry,
    publish_from_vault,
    sign_unpublish,
)
from atlas.ai.vault_library import VaultLibrarySource, import_bytes, shelf
from atlas.crypto.sign import generate_sig_keypair
from atlas.keys.identity import handle_of
from atlas.session.vault import Vault


def _persona():
    kp = generate_sig_keypair()
    return kp, handle_of(kp.public.encode()).hex()


def test_publish_copies_citeable_entry_under_handle_content_stays_in_vault():
    v = Vault(os.urandom(32))
    import_bytes(v, id=b"doc1", author="me", title="Tide notes", content=b"the tide rises",
                 tags=["tide"])
    reg = FederatedRegister()
    kp, handle_hex = _persona()
    entry = publish_from_vault(v, reg, item_id=b"doc1", signer=kp, license="cc-by")
    assert entry.item.author == handle_hex            # attributed to the persona handle, not System-ID
    assert entry.item.origin == "published"
    assert entry.item.license == "cc-by"
    # the register carries only the citeable entry — no content bytes
    assert not hasattr(entry, "content")
    # the content still lives in the persona's own vault (publish is a copy, not a move)
    assert "__atlas.library.content__/" + b"doc1".hex() in v
    # discoverable in the global library
    assert [i.id for i in reg.search("tide")] == [b"doc1"]


def test_forged_author_or_signature_is_rejected():
    reg = FederatedRegister()
    v = Vault(os.urandom(32))
    import_bytes(v, id=b"doc1", author="me", title="t", content=b"x", tags=["tide"])
    kp, _ = _persona()
    good = publish_from_vault(v, reg, item_id=b"doc1", signer=kp, license="cc-by")
    # tamper with the entry's item (title) but keep the old signature -> rejected
    from dataclasses import replace
    forged = replace(good, item=replace(good.item, title="hijacked"))
    with pytest.raises(PublishError):
        reg.publish(forged)
    # claim someone else's handle -> signature/handle mismatch rejected
    other_kp, _ = _persona()
    mismatched = make_entry(replace(good.item, title="x"), other_kp)   # signed by other key
    mismatched = replace(mismatched, item=good.item)                   # ...but author = original handle
    with pytest.raises(PublishError):
        reg.publish(mismatched)


def test_license_by_default_when_unset_stays_reserved():
    v = Vault(os.urandom(32))
    import_bytes(v, id=b"doc1", author="me", title="Tide notes", content=b"x", tags=["tide"])
    reg = FederatedRegister()
    kp, _ = _persona()
    entry = publish_from_vault(v, reg, item_id=b"doc1", signer=kp)     # no license chosen
    assert entry.item.license == ALL_RIGHTS_RESERVED                   # import default carried through
    # discoverable but not usable: read via a consumer registry
    consumer = LibraryRegistry()
    consumer.register(reg)
    hit = {h.hit.item: h.hit for h in consumer.search("tide")}[b"doc1"]
    assert hit.licensed is False and hit.purchasable is False          # surfaced as "ask"


def test_another_persona_discovers_it_via_the_shared_register():
    reg = FederatedRegister()                          # the ONE global library
    author_v = Vault(os.urandom(32))
    import_bytes(author_v, id=b"pub", author="me", title="Public tide guide", content=b"x",
                 tags=["tide"])
    kp, _ = _persona()
    publish_from_vault(author_v, reg, item_id=b"pub", signer=kp, license="open")
    # a DIFFERENT persona composes its own registry: its own (empty) vault + the shared register
    reader_v = Vault(os.urandom(32))
    reader = LibraryRegistry()
    reader.register(VaultLibrarySource("vault", reader_v))
    reader.register(reg)
    hits = {h.hit.item: h.source for h in reader.search("tide")}
    assert hits == {b"pub": "register"}                # sees the global work, none of the author's private shelf


def test_only_publisher_can_unpublish():
    reg = FederatedRegister()
    v = Vault(os.urandom(32))
    import_bytes(v, id=b"doc1", author="me", title="t", content=b"x", tags=["tide"])
    kp, _ = _persona()
    publish_from_vault(v, reg, item_id=b"doc1", signer=kp, license="cc-by")
    other_kp, _ = _persona()
    with pytest.raises(PublishError):
        reg.unpublish(b"doc1", sign_unpublish(other_kp, b"doc1"))     # wrong key
    assert reg.search("tide")                                          # still there
    reg.unpublish(b"doc1", sign_unpublish(kp, b"doc1"))               # publisher's key
    assert reg.search("tide") == []
