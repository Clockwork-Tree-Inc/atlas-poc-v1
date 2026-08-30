"""Age assurance (#30 + #22 eID slice): eID-rooted, consumable (single-use, unlinkable, band-only)
age tokens; bidirectional gate (adult spaces exclude minors, child spaces exclude adults) with a
guardian exception (eID-verified adult + guardian attestation for THAT space)."""

import os

import pytest

from atlas.age import (
    AgeError,
    admit_adult_space,
    admit_child_space,
    bands_for,
    issue_age_tokens,
    issue_eid_assertion,
    satisfies,
    verify_eid_assertion,
    verify_token,
)
from atlas.crypto.sign import generate_sig_keypair
from atlas.keys.identity import handle_of
from atlas.participant import issue_attestation

REF = 2026


def _key():
    kp = generate_sig_keypair()
    return kp, handle_of(kp.public.encode())


def _serials(n):
    return [os.urandom(16) for _ in range(n)]


def test_bands_and_satisfies():
    assert bands_for(2000, REF) == {"18+", "21+"}      # 26yo
    assert bands_for(2010, REF) == {"under-18"}        # 16yo
    assert bands_for(2007, REF) == {"18+"}             # 19yo — adult, not yet 21
    assert satisfies("21+", "18+") and satisfies("21+", "21+")   # 21+ implies 18+
    assert not satisfies("18+", "21+")
    assert satisfies("under-18", "under-18") and not satisfies("under-18", "18+")


def test_eid_assertion_verifies_and_forgery_fails():
    issuer, _ = _key()
    _kp, subject = _key()
    eid = issue_eid_assertion(issuer, issuer_name="Passport-Authority", subject=subject, birth_year=2000)
    assert verify_eid_assertion(eid)
    eid.birth_year = 2015                              # tamper -> invalid
    assert not verify_eid_assertion(eid)


def test_issue_tokens_requires_eid_to_satisfy_band():
    authority, _ = _key()
    issuer, _ = _key()
    _kp, subject = _key()
    minor_eid = issue_eid_assertion(issuer, issuer_name="PA", subject=subject, birth_year=2012)  # 14yo
    with pytest.raises(AgeError):                      # can't mint 18+ for a minor
        issue_age_tokens(authority, authority_name="AgeVerifier", eid=minor_eid, ref_year=REF,
                         band="18+", count=1, serials=_serials(1))
    toks = issue_age_tokens(authority, authority_name="AgeVerifier", eid=minor_eid, ref_year=REF,
                            band="under-18", count=3, serials=_serials(3))
    assert len(toks) == 3 and all(verify_token(t) for t in toks)


def test_tokens_are_single_use_and_identity_free():
    authority, _ = _key()
    issuer, _ = _key()
    _kp, subject = _key()
    eid = issue_eid_assertion(issuer, issuer_name="PA", subject=subject, birth_year=2000)
    toks = issue_age_tokens(authority, authority_name="AgeVerifier", eid=eid, ref_year=REF,
                            band="18+", count=2, serials=_serials(2))
    # no identity in a token: the subject handle appears nowhere
    assert all(subject not in t.serial and subject not in t.body() for t in toks)
    # different tokens don't correlate (distinct serials)
    assert toks[0].serial != toks[1].serial
    trusted = {authority.public.encode()}
    seen = set()
    assert admit_adult_space(toks[0], trusted_authority_keys=trusted, seen_serials=seen) is True
    assert admit_adult_space(toks[0], trusted_authority_keys=trusted, seen_serials=seen) is False  # consumed


def test_adult_space_excludes_minors_and_untrusted_authorities():
    authority, _ = _key()
    other, _ = _key()
    issuer, _ = _key()
    _kp, adult = _key()
    _kp2, minor = _key()
    adult_eid = issue_eid_assertion(issuer, issuer_name="PA", subject=adult, birth_year=2000)
    minor_eid = issue_eid_assertion(issuer, issuer_name="PA", subject=minor, birth_year=2014)
    adult_tok = issue_age_tokens(authority, authority_name="AV", eid=adult_eid, ref_year=REF,
                                 band="18+", count=1, serials=_serials(1))[0]
    minor_tok = issue_age_tokens(authority, authority_name="AV", eid=minor_eid, ref_year=REF,
                                 band="under-18", count=1, serials=_serials(1))[0]
    trusted = {authority.public.encode()}
    assert admit_adult_space(adult_tok, trusted_authority_keys=trusted, seen_serials=set()) is True
    assert admit_adult_space(minor_tok, trusted_authority_keys=trusted, seen_serials=set()) is False
    # a valid token from an authority the consumer doesn't trust is rejected
    assert admit_adult_space(adult_tok, trusted_authority_keys={other.public.encode()},
                             seen_serials=set()) is False


def test_child_space_minor_admitted_adult_excluded_guardian_allowed():
    authority, _ = _key()
    issuer, _ = _key()
    _kp, minor = _key()
    _kp2, parent = _key()
    space = "kids-lobby-7"
    minor_eid = issue_eid_assertion(issuer, issuer_name="PA", subject=minor, birth_year=2015)
    parent_eid = issue_eid_assertion(issuer, issuer_name="PA", subject=parent, birth_year=1985)
    minor_tok = issue_age_tokens(authority, authority_name="AV", eid=minor_eid, ref_year=REF,
                                 band="under-18", count=1, serials=_serials(1))[0]
    parent_tok = issue_age_tokens(authority, authority_name="AV", eid=parent_eid, ref_year=REF,
                                  band="18+", count=2, serials=_serials(2))
    trusted = {authority.public.encode()}

    # a minor gets in
    assert admit_child_space(child_space_id=space, trusted_authority_keys=trusted,
                             seen_serials=set(), token=minor_tok) == "minor"
    # a bare adult (18+ token, no guardian attestation) is excluded
    assert admit_child_space(child_space_id=space, trusted_authority_keys=trusted,
                             seen_serials=set(), guardian_token=parent_tok[0]) is None
    # an adult WITH a guardian attestation for THIS space is admitted as guardian
    gatt = issue_attestation(authority, authority_name="AV", subject=parent,
                             claim=f"guardian-in:{space}")
    assert admit_child_space(child_space_id=space, trusted_authority_keys=trusted, seen_serials=set(),
                             guardian_token=parent_tok[0], guardian_attestation=gatt) == "guardian"
    # ...but a guardian attestation for a DIFFERENT space does not admit here
    gatt_other = issue_attestation(authority, authority_name="AV", subject=parent,
                                   claim="guardian-in:some-other-space")
    assert admit_child_space(child_space_id=space, trusted_authority_keys=trusted, seen_serials=set(),
                             guardian_token=parent_tok[1], guardian_attestation=gatt_other) is None
