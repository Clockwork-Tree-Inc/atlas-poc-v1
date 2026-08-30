"""Public web gateway (#31): a did:web mirror of the persona's key + a signed static public page
that hands off into the app. No-compromise: only public-persona data, only this persona's works,
key/handle/name all bound, authenticity independent of TLS."""

from types import SimpleNamespace

import pytest

from atlas.ai.librarian import CorpusItem
from atlas.ai.publish import FederatedRegister, make_entry
from atlas.crypto.sign import generate_sig_keypair
from atlas.interop.did import did_for, resolve
from atlas.interop.web_gateway import (
    GatewayError,
    build_public_page,
    did_web_document,
    did_web_id,
    parse_universal_link,
    verify_public_page,
)
from atlas.keys.identity import handle_of
from atlas.marketplace import EntityClass
from atlas.names import claim_name
from atlas.participant import create_profile


def _persona(name_hint="alice"):
    kp = generate_sig_keypair()
    handle = handle_of(kp.public.encode())
    ident = SimpleNamespace(keypair=kp, public=kp.public, handle=handle)
    return kp, handle, ident


def _published_work(register, kp, handle, *, id, title, license="cc-by"):
    item = CorpusItem(id=id, author=handle.hex(), title=title, tags=("tide",),
                      license=license, origin="published")
    register.publish(make_entry(item, kp))


def test_did_web_document_roundtrips_to_same_key():
    kp, _h, _ = _persona()
    doc = did_web_document(kp.public, "alice.example")
    assert doc["id"] == did_web_id("alice.example") == "did:web:alice.example"
    assert doc["alsoKnownAs"] == [did_for(kp.public)]      # bridge web <-> atlas (same key)
    assert resolve(doc) == kp.public                        # a web verifier recovers the exact key


def test_build_and_verify_public_page():
    kp, handle, ident = _persona()
    reg = FederatedRegister()
    _published_work(reg, kp, handle, id=b"w1", title="Tide guide")
    profile = create_profile(handle=handle, public=kp.public, entity_class=EntityClass.INDIVIDUAL)
    profile.go_public(display_name="Alice", bio="tide photographer", links=("mastodon",))
    nc = claim_name(ident, "alice")
    page = build_public_page(profile=profile, name_claim=nc, signer=kp, domain="alice.example",
                             register=reg)
    assert page.display_name == "Alice" and page.bio == "tide photographer"
    assert page.open_in_atlas == "https://atlas.id/alice"
    assert [w["title"] for w in page.works] == ["Tide guide"]
    assert verify_public_page(page, nc) is True


def test_private_persona_has_no_web_page():
    kp, handle, ident = _persona()
    profile = create_profile(handle=handle, public=kp.public, entity_class=EntityClass.INDIVIDUAL)
    # anonymous (default) -> no page
    nc = claim_name(ident, "ghost")
    with pytest.raises(GatewayError):
        build_public_page(profile=profile, name_claim=nc, signer=kp, domain="x.example",
                          register=FederatedRegister())


def test_tampered_page_fails_verification_independent_of_tls():
    kp, handle, ident = _persona()
    profile = create_profile(handle=handle, public=kp.public, entity_class=EntityClass.INDIVIDUAL)
    profile.go_public(display_name="Alice")
    nc = claim_name(ident, "alice")
    page = build_public_page(profile=profile, name_claim=nc, signer=kp, domain="alice.example",
                             register=FederatedRegister())
    page.bio = "hijacked"                                   # a MITM edits the served page
    assert verify_public_page(page, nc) is False            # signature (not TLS) catches it


def test_only_this_personas_works_are_included():
    kp, handle, ident = _persona()
    other_kp = generate_sig_keypair()
    other_handle = handle_of(other_kp.public.encode())
    reg = FederatedRegister()
    _published_work(reg, kp, handle, id=b"mine", title="My tide")
    _published_work(reg, other_kp, other_handle, id=b"theirs", title="Their tide")
    profile = create_profile(handle=handle, public=kp.public, entity_class=EntityClass.INDIVIDUAL)
    profile.go_public(display_name="Alice")
    nc = claim_name(ident, "alice")
    page = build_public_page(profile=profile, name_claim=nc, signer=kp, domain="alice.example",
                             register=reg)
    assert [w["title"] for w in page.works] == ["My tide"]  # never another persona's work


def test_name_claim_and_signer_must_bind_the_handle():
    kp, handle, ident = _persona()
    profile = create_profile(handle=handle, public=kp.public, entity_class=EntityClass.INDIVIDUAL)
    profile.go_public(display_name="Alice")
    # a name claim for a DIFFERENT handle
    _kp2, _h2, ident2 = _persona()
    wrong_nc = claim_name(ident2, "bob")
    with pytest.raises(GatewayError):
        build_public_page(profile=profile, name_claim=wrong_nc, signer=kp, domain="x", register=FederatedRegister())
    # a signer that doesn't control the profile handle
    good_nc = claim_name(ident, "alice")
    with pytest.raises(GatewayError):
        build_public_page(profile=profile, name_claim=good_nc, signer=generate_sig_keypair(),
                          domain="x", register=FederatedRegister())


def test_parse_universal_link():
    assert parse_universal_link("https://atlas.id/alice") == "alice"
    assert parse_universal_link("atlas://bob") == "bob"
    assert parse_universal_link("https://example.com/whatever") is None
