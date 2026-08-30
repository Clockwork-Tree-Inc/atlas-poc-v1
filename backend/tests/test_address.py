"""Addressing + nameplate resolver: parse, publish/resolve, findable vs receptive, private routing."""
import pytest

from atlas.crypto.sign import keypair_from_seed
from atlas.interop import address as ad
from atlas.interop import trust_publish as tp
from atlas import trust_graph as tg


def kp(n):
    return keypair_from_seed(bytes([n]) * 32)


def test_parse_and_format_address():
    a = ad.parse_address("ada@example.town")
    assert a.local == "ada" and a.place == "example.town"
    assert str(a) == "ada@example.town"
    assert ad.nameplate_url(a) == "https://example.town/.well-known/atlas/ada.json"
    for bad in ["noatsign", "a@b@c", "@place", "local@"]:
        with pytest.raises(ad.AddressError):
            ad.parse_address(bad)


def test_publish_and_resolve_a_nameplate():
    persona = kp(1)
    addr = ad.parse_address("ada@example.id")
    settings = ad.DiscoverySettings(findable=True, receptive=ad.ReceptiveMode.CODE_ONLY)
    np = ad.build_nameplate(persona, address=addr, display_name="Ada Rivera", settings=settings)
    served = {ad.nameplate_url(addr): np.to_json()}
    got = ad.resolve("ada@example.id", fetch=lambda u: served[u])
    assert got.key.encode() == persona.public.encode()
    assert got.display_name == "Ada Rivera"
    assert got.receptive is ad.ReceptiveMode.CODE_ONLY


def test_unfindable_persona_publishes_no_nameplate():
    persona = kp(1)
    addr = ad.parse_address("ghost@example.id")
    np = ad.build_nameplate(persona, address=addr, display_name="",
                            settings=ad.DiscoverySettings(findable=False, receptive=ad.ReceptiveMode.OPEN))
    assert np is None       # nothing to serve — unfindable


def test_host_cannot_forge_a_nameplate():
    persona, attacker = kp(1), kp(2)
    addr = ad.parse_address("ada@example.id")
    np = ad.build_nameplate(persona, address=addr, display_name="Ada Rivera",
                            settings=ad.DiscoverySettings(findable=True, receptive=ad.ReceptiveMode.OPEN))
    # a malicious host swaps in the attacker's key but can't re-sign as the persona
    np.key = attacker.public
    served = {ad.nameplate_url(addr): np.to_json()}
    with pytest.raises(ad.AddressError):
        ad.resolve("ada@example.id", fetch=lambda u: served[u])


def test_nameplate_can_carry_the_trust_bundle():
    persona, gov = kp(1), kp(3)
    # a tiny self-published bundle rides along in the nameplate
    edge = tg.authorize(gov, grantee=persona.public, remit=tg.ACCREDITOR)
    bundle = tp.build_trust_bundle(publisher=persona, domain="example.id", edges=[edge])
    addr = ad.parse_address("ada@example.id")
    np = ad.build_nameplate(persona, address=addr, display_name="Ada Rivera",
                            settings=ad.DiscoverySettings(findable=True, receptive=ad.ReceptiveMode.OPEN),
                            trust_bundle=bundle)
    got = ad.resolve("ada@example.id", fetch=lambda u: {ad.nameplate_url(addr): np.to_json()}[u])
    assert got.trust_bundle is not None
    assert tp.verify_trust_bundle(got.trust_bundle)


def test_findable_and_receptive_are_independent():
    # findable + closed: discoverable, but no one can open a channel
    s1 = ad.DiscoverySettings(findable=True, receptive=ad.ReceptiveMode.CLOSED)
    assert not s1.accepts_contact(has_valid_code=True, is_known_contact=True)
    # unfindable + open-to-code: unlisted, yet reachable by anyone holding a code
    s2 = ad.DiscoverySettings(findable=False, receptive=ad.ReceptiveMode.CODE_ONLY)
    assert s2.accepts_contact(has_valid_code=True, is_known_contact=False)
    assert not s2.accepts_contact(has_valid_code=False, is_known_contact=False)
    # contacts-only
    s3 = ad.DiscoverySettings(findable=True, receptive=ad.ReceptiveMode.CONTACTS_ONLY)
    assert s3.accepts_contact(has_valid_code=False, is_known_contact=True)
    assert not s3.accepts_contact(has_valid_code=True, is_known_contact=False)


def test_private_routing_many_addresses_one_inbox():
    work, personal = kp(4), kp(5)
    inbox = b"\x11" * 16
    rt = ad.RoutingTable()
    # two faces (a work persona and a personal one) both quietly converge into one real inbox
    rt.point("ada@work.example", work.public)
    rt.point("ada@personal.example", personal.public)
    rt.converge(work.public, inbox)
    rt.converge(personal.public, inbox)
    assert rt.persona_for("ada@work.example") == work.public.encode()
    assert rt.inbox_for_address("ada@work.example") == inbox
    assert rt.inbox_for_address("ada@personal.example") == inbox     # same inbox, sender never sees it
    assert rt.inbox_for_address("unknown@nowhere.com") is None
