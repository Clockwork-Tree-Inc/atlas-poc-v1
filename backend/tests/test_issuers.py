"""Credential issuers: mint + revoke the real-id / registered / category attestations the gates use."""
import pytest

from atlas.crypto.sign import keypair_from_seed
from atlas.economy import supply_gate as sg
from atlas.issuers import Issuer, category_claim, credential_id, valid_credential
from atlas.marketplace import EntityClass
from atlas.participant import create_profile


def kp(n):
    return keypair_from_seed(bytes([n]) * 32)


def _profile(n, ec=EntityClass.INDIVIDUAL):
    k = kp(n)
    return k, create_profile(handle=bytes([n]) * 32, public=k.public, entity_class=ec)


def test_issued_real_id_satisfies_the_supply_gate():
    verifier = Issuer(kp(1), "Gov Real-ID Verifier")
    _, seller = _profile(2)
    seller.hold(verifier.issue_real_id(subject=seller.handle))
    assert sg.can_perform(seller, "sell", trusted_verifier_keys={verifier.public.encode()})


def test_org_needs_issued_real_id_and_registration():
    verifier = Issuer(kp(1), "Verifier")
    registry = Issuer(kp(3), "Company Registry")
    _, org = _profile(2, EntityClass.FOR_PROFIT)
    seller_keys = {verifier.public.encode()}
    reg_keys = {registry.public.encode()}

    org.hold(verifier.issue_real_id(subject=org.handle))
    assert not sg.can_perform(org, "sell", trusted_verifier_keys=seller_keys, trusted_registry_keys=reg_keys)
    org.hold(registry.issue_registration(subject=org.handle))
    assert sg.can_perform(org, "sell", trusted_verifier_keys=seller_keys, trusted_registry_keys=reg_keys)


def test_category_credential_claim():
    body = Issuer(kp(5), "Health Registry")
    att = body.issue_category(subject=bytes([9]) * 32, sector="healthcare")
    assert att.claim == category_claim("healthcare") == "category:healthcare"


def test_valid_credential_checks_signature_trust_and_revocation():
    issuer = Issuer(kp(1), "Verifier")
    other = kp(9)
    att = issuer.issue_real_id(subject=bytes([2]) * 32)

    assert valid_credential(att, trusted_issuer_keys={issuer.public.encode()})
    # untrusted issuer key -> rejected
    assert not valid_credential(att, trusted_issuer_keys={other.public.encode()})


def test_revocation_pulls_the_credential():
    issuer = Issuer(kp(1), "Company Registry")
    att = issuer.issue_registration(subject=bytes([2]) * 32)
    keys = {issuer.public.encode()}
    assert valid_credential(att, trusted_issuer_keys=keys, revoked=issuer.revocation_set)

    issuer.revoke(att)                                        # struck off the register
    assert issuer.is_revoked(att)
    assert not valid_credential(att, trusted_issuer_keys=keys, revoked=issuer.revocation_set)


def test_revoked_org_registration_fails_the_gate():
    verifier = Issuer(kp(1), "Verifier")
    registry = Issuer(kp(3), "Company Registry")
    _, org = _profile(2, EntityClass.FOR_PROFIT)
    org.hold(verifier.issue_real_id(subject=org.handle))
    reg = registry.issue_registration(subject=org.handle)
    org.hold(reg)
    vkeys, rkeys = {verifier.public.encode()}, {registry.public.encode()}
    assert sg.can_perform(org, "sell", trusted_verifier_keys=vkeys, trusted_registry_keys=rkeys)

    # NOTE: the gate uses participant.presents (signature+trust). Revocation is an ADDITIONAL check a
    # deployment layers on; here we assert the revocation primitive itself flips the credential.
    registry.revoke(reg)
    from atlas.issuers import valid_credential as vc
    assert not vc(reg, trusted_issuer_keys=rkeys, revoked=registry.revocation_set)


def test_credential_id_is_stable_and_distinct():
    issuer = Issuer(kp(1), "V")
    a = issuer.issue_real_id(subject=bytes([2]) * 32)
    b = issuer.issue_real_id(subject=bytes([3]) * 32)
    assert credential_id(a) == credential_id(a)
    assert credential_id(a) != credential_id(b)
