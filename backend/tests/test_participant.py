"""Participant & profile (#27): everyone/everything is one participant class; self-service profiles
on the anonymous->public->verified spectrum; credential-authorities-as-participants attest others;
verification-not-authority (trust binds to the authority KEY the consumer chooses, not a name)."""

import pytest

from atlas.crypto.sign import generate_sig_keypair
from atlas.keys.identity import handle_of
from atlas.marketplace import EntityClass
from atlas.participant import (
    ParticipantError,
    Visibility,
    create_profile,
    issue_attestation,
    presents,
    verify_attestation,
)


def _party(entity=EntityClass.INDIVIDUAL):
    kp = generate_sig_keypair()
    handle = handle_of(kp.public.encode())
    return kp, handle, create_profile(handle=handle, public=kp.public, entity_class=entity)


def test_self_service_profile_anonymous_by_default_then_public():
    _kp, _h, p = _party()
    assert p.visibility is Visibility.ANONYMOUS and p.display_name == ""
    p.go_public(display_name="Alice", bio="tide photographer", links=("did:atlas:alice",))
    assert p.visibility is Visibility.PUBLIC and p.display_name == "Alice"
    p.go_anonymous()
    assert p.visibility is Visibility.ANONYMOUS and p.display_name == ""


def test_entity_classes_are_the_canonical_set():
    # Three top-level kinds: individual, business (nonprofit/for-profit), agent. No protected-trait
    # / no religious-org classes (Inv 8). Businesses are the two registered-legal-entity fiscal types.
    assert {e.value for e in EntityClass} == {"individual", "nonprofit", "for_profit", "agent"}
    assert EntityClass.NONPROFIT.is_organization and EntityClass.FOR_PROFIT.is_organization
    assert not EntityClass.INDIVIDUAL.is_organization and not EntityClass.AGENT.is_organization
    assert not EntityClass.AGENT.can_be_principal   # agents never root authority
    _kp, _h, org = _party(EntityClass.NONPROFIT)
    assert org.entity_class is EntityClass.NONPROFIT


def test_authority_attests_subject_and_profile_shows_verified():
    # an authority is itself a participant (here a nonprofit medical board)
    auth_kp, _ah, auth_profile = _party(EntityClass.NONPROFIT)
    auth_profile.go_public(display_name="Medical Board")
    _kp, subject_h, doc = _party()
    doc.go_public(display_name="Dr Bob")
    att = issue_attestation(auth_kp, authority_name="Medical Board", subject=subject_h,
                            claim="licensed-physician")
    doc.hold(att)
    assert doc.verified_by() == ("Medical Board",)
    assert doc.is_verified is True


def test_forged_or_misdirected_attestation_is_rejected():
    auth_kp, _ah, _ap = _party(EntityClass.NONPROFIT)
    _kp, subject_h, subj = _party()
    att = issue_attestation(auth_kp, authority_name="Board", subject=subject_h, claim="x")
    # tamper the claim but keep the old signature -> invalid
    att.claim = "hijacked"
    assert verify_attestation(att) is False
    with pytest.raises(ParticipantError):
        subj.hold(att)
    # an attestation about someone else can't be held by me
    good = issue_attestation(auth_kp, authority_name="Board", subject=b"someone-else", claim="x")
    with pytest.raises(ParticipantError):
        subj.hold(good)


def test_verification_not_authority_consumer_chooses_trusted_keys():
    real_kp, _rh, _rp = _party(EntityClass.NONPROFIT)
    impostor_kp, _ih, _ip = _party(EntityClass.NONPROFIT)   # same NAME, different key
    _kp, subject_h, p = _party()
    p.go_public(display_name="Dr Bob")
    # impostor signs a valid-looking attestation using the SAME display name
    fake = issue_attestation(impostor_kp, authority_name="Medical Board", subject=subject_h,
                             claim="licensed-physician")
    p.hold(fake)                                            # signature is valid (just not trusted)
    assert verify_attestation(fake) is True
    # a consumer that trusts only the REAL board's key rejects it
    trusted = {real_kp.public.encode()}
    assert presents(p, claim="licensed-physician", trusted_authority_keys=trusted) is False
    # ...and accepts once the real board attests
    real = issue_attestation(real_kp, authority_name="Medical Board", subject=subject_h,
                             claim="licensed-physician")
    p.hold(real)
    assert presents(p, claim="licensed-physician", trusted_authority_keys=trusted) is True
