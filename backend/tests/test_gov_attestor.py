"""Gov-office recovery attestor (#22 half): a government office as a WITTING, INSTITUTIONAL guardian
whose approval is gated on IN-PERSON eID + liveness — and, by the standing anti-all-institutional
invariant, can never recover you without a non-institutional live guardian."""

import os

import pytest

from atlas.age import issue_eid_assertion
from atlas.crypto.sign import generate_sig_keypair
from atlas.keys.identity import handle_of
from atlas.recovery.gov_attestor import (
    GovOfficeAttestor,
    NotInPerson,
    approvals_from_attestations,
    attest_recovery,
    verify_recovery_attestation,
)
from atlas.recovery.guardianship import (
    ApprovalsNotMet,
    Guardian,
    GuardianKind,
    GuardianshipPolicy,
    InstitutionalThresholdError,
    reconstruct_under_guardianship,
    seal_under_guardianship,
)
from atlas.recovery.threshold_seal import Custodian, StorageLocation, ThresholdNotMet


def _office(name="Passport-Office"):
    return GovOfficeAttestor(name=name, keypair=generate_sig_keypair())


def _persona():
    kp = generate_sig_keypair()
    return kp, handle_of(kp.public.encode())


def _eid(subject, *, issuer=None, birth_year=1990):
    issuer = issuer or generate_sig_keypair()
    return issue_eid_assertion(issuer, issuer_name="PA", subject=subject, birth_year=birth_year)


def test_attest_gated_on_in_person_eid_and_liveness():
    office = _office()
    _kp, subject = _persona()
    req = os.urandom(16)
    att = attest_recovery(office, subject_handle=subject, request_id=req, eid=_eid(subject), live=True)
    assert verify_recovery_attestation(att)
    # refuses without a live human
    with pytest.raises(NotInPerson):
        attest_recovery(office, subject_handle=subject, request_id=req, eid=_eid(subject), live=False)
    # refuses an eID for a different persona
    _kp2, other = _persona()
    with pytest.raises(NotInPerson):
        attest_recovery(office, subject_handle=subject, request_id=req, eid=_eid(other), live=True)
    # refuses a forged eID
    bad = _eid(subject)
    bad.birth_year = 3000
    with pytest.raises(NotInPerson):
        attest_recovery(office, subject_handle=subject, request_id=req, eid=bad, live=True)


def test_office_is_a_witting_institutional_guardian():
    g = _office("DMV").guardian()
    assert g.institutional is True
    assert g.kind is GuardianKind.WITTING
    assert g.label == "gov:DMV"


def test_all_institutional_quorum_is_rejected_at_construction():
    # two institutions, threshold 2 -> an all-institutional subset could recover: rejected
    g1 = _office("A").guardian()
    g2 = _office("B").guardian()
    with pytest.raises(InstitutionalThresholdError):
        GuardianshipPolicy(guardians=(g1, g2), m=2)


def _setup_quorum():
    office = _office()
    person = Guardian(custodian=Custodian(label="person:mom", institutional=False),
                      kind=GuardianKind.WITTING)
    policy = GuardianshipPolicy(guardians=(office.guardian(), person), m=2, min_witting_approvals=2)
    user_half = os.urandom(32)
    secret = b"recoverable-enrollment-material"
    sealed, shares = seal_under_guardianship(secret, user_half=user_half, policy=policy,
                                             storage=StorageLocation.GUARDIANS, context=b"rec")
    gov_share, person_share = shares            # order matches policy.guardians
    return office, person, policy, user_half, secret, sealed, gov_share, person_share


def test_recovery_succeeds_with_in_person_office_plus_live_person():
    office, person, policy, user_half, secret, sealed, gov_share, person_share = _setup_quorum()
    _kp, subject = _persona()
    att = attest_recovery(office, subject_handle=subject, request_id=os.urandom(16),
                          eid=_eid(subject), live=True)
    approvals = approvals_from_attestations([office], [att]) + ["person:mom"]
    out = reconstruct_under_guardianship(sealed, user_half=user_half,
                                         presented_shares=[gov_share, person_share],
                                         policy=policy, witting_approvals=approvals)
    assert out == secret


def test_office_alone_cannot_recover():
    office, person, policy, user_half, secret, sealed, gov_share, person_share = _setup_quorum()
    _kp, subject = _persona()
    att = attest_recovery(office, subject_handle=subject, request_id=os.urandom(16),
                          eid=_eid(subject), live=True)
    approvals = approvals_from_attestations([office], [att]) + ["person:mom"]
    # only the office's own share -> the anti-all-institutional invariant rejects it (a
    # non-institutional party is required), before threshold is even reached
    with pytest.raises(InstitutionalThresholdError):
        reconstruct_under_guardianship(sealed, user_half=user_half, presented_shares=[gov_share],
                                       policy=policy, witting_approvals=approvals)


def test_without_office_in_person_attestation_recovery_is_blocked():
    office, person, policy, user_half, secret, sealed, gov_share, person_share = _setup_quorum()
    # the office never attested (no in-person verify) -> its approval label is absent
    with pytest.raises(ApprovalsNotMet):
        reconstruct_under_guardianship(sealed, user_half=user_half,
                                       presented_shares=[gov_share, person_share],
                                       policy=policy, witting_approvals=["person:mom"])
