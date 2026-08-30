"""Supply-side Real-ID gate: buy anonymous, sell/earn/own-org only with a trusted Real-ID."""
import pytest

from atlas.crypto.sign import keypair_from_seed
from atlas.economy import supply_gate as sg
from atlas.marketplace import EntityClass
from atlas.participant import create_profile, issue_attestation


def kp(n):
    return keypair_from_seed(bytes([n]) * 32)


def _profile(n, entity_class=EntityClass.INDIVIDUAL):
    k = kp(n)
    return k, create_profile(handle=bytes([n]) * 32, public=k.public, entity_class=entity_class)


def _give(profile, subject_handle, authority_kp, claim):
    att = issue_attestation(authority_kp, authority_name="Verifier", subject=subject_handle, claim=claim)
    profile.hold(att)


def test_anyone_can_buy_anonymously():
    _, buyer = _profile(2)
    assert sg.can_perform(buyer, "buy")
    assert sg.can_perform(buyer, "browse")
    assert not sg.can_perform(buyer, "sell")             # but can't sell without Real-ID


def test_individual_with_trusted_real_id_can_sell():
    verifier = kp(1)
    k, seller = _profile(2)
    _give(seller, seller.handle, verifier, sg.REAL_ID_CLAIM)
    assert sg.can_perform(seller, "sell", trusted_verifier_keys={verifier.public.encode()})
    assert sg.can_perform(seller, "earn", trusted_verifier_keys={verifier.public.encode()})


def test_real_id_from_untrusted_verifier_does_not_count():
    verifier, other = kp(1), kp(9)
    _, seller = _profile(2)
    _give(seller, seller.handle, verifier, sg.REAL_ID_CLAIM)
    # checker trusts a DIFFERENT key -> the credential doesn't satisfy the gate
    assert not sg.can_perform(seller, "sell", trusted_verifier_keys={other.public.encode()})


def test_organization_needs_real_id_AND_registration():
    verifier, registry = kp(1), kp(3)
    _, org = _profile(2, EntityClass.FOR_PROFIT)
    _give(org, org.handle, verifier, sg.REAL_ID_CLAIM)
    vkeys = {verifier.public.encode()}
    rkeys = {registry.public.encode()}
    # real-id only -> not enough for an org
    assert not sg.can_perform(org, "sell", trusted_verifier_keys=vkeys, trusted_registry_keys=rkeys)
    _give(org, org.handle, registry, sg.REGISTRATION_CLAIM)
    assert sg.can_perform(org, "sell", trusted_verifier_keys=vkeys, trusted_registry_keys=rkeys)


def test_nonprofit_is_an_organization_for_the_gate():
    verifier, registry = kp(1), kp(3)
    _, org = _profile(2, EntityClass.NONPROFIT)
    _give(org, org.handle, verifier, sg.REAL_ID_CLAIM)
    assert not sg.can_perform(org, "provide", trusted_verifier_keys={verifier.public.encode()},
                              trusted_registry_keys={registry.public.encode()})


def test_agent_is_never_a_direct_supply_actor():
    verifier = kp(1)
    _, agent = _profile(2, EntityClass.AGENT)
    _give(agent, agent.handle, verifier, sg.REAL_ID_CLAIM)   # even with a real-id
    assert not sg.can_perform(agent, "sell", trusted_verifier_keys={verifier.public.encode()})
    assert sg.can_perform(agent, "buy")                       # an agent may buy for its principal


def test_unknown_action_raises():
    _, p = _profile(2)
    with pytest.raises(sg.SupplyGateError):
        sg.can_perform(p, "teleport")
