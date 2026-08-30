"""Custom profile fields, LinkedIn-style: claims, many endorsers per value, openable proofs, no trust."""
import pytest

from atlas.crypto.sign import keypair_from_seed
from atlas import profile_fields as pf
from atlas.participant import verify_attestation


def kp(n):
    return keypair_from_seed(bytes([n]) * 32)


def test_unendorsed_value_is_just_a_claim():
    me = kp(1)
    v = pf.view(pf.make_field(me, "favourite colour", "blue"))
    assert v.owner_signed
    assert v.entries[0].value == "blue"
    assert v.entries[0].confirmed is False
    assert v.entries[0].endorsers == ()


def test_tampered_claim_is_flagged():
    me = kp(1)
    f = pf.make_field(me, "favourite colour", "blue")
    f.values = ("red",)                     # edited without re-signing
    assert pf.view(f).owner_signed is False


def test_many_people_and_orgs_can_endorse_a_value():
    me = kp(1)
    # 10 people + 3 organizations endorse BSc; 2 endorse MSc
    mbbs_endorsers = [kp(n) for n in range(10, 23)]     # 13 keys
    md_endorsers = [kp(30), kp(31)]
    ends = [pf.endorse(e, subject=me.public, label="work", value="BSc", endorser_name=f"E{i}")
            for i, e in enumerate(mbbs_endorsers)]
    ends += [pf.endorse(e, subject=me.public, label="work", value="MSc") for e in md_endorsers]

    f = pf.make_field(me, "work", ["BSc", "MSc", "doctor"], endorsements=ends)
    v = pf.view(f)
    by_value = {e.value: e for e in v.entries}
    assert len(by_value["BSc"].endorsers) == 13
    assert len(by_value["MSc"].endorsers) == 2
    assert by_value["doctor"].confirmed is False        # a plain self-asserted claim, nobody endorsed it
    assert by_value["BSc"].confirmed and by_value["MSc"].confirmed


def test_each_endorsement_is_an_openable_proof():
    me, school = kp(1), kp(2)
    e = pf.endorse(school, subject=me.public, label="work", value="BSc", endorser_name="Northgate University")
    v = pf.view(pf.make_field(me, "work", "BSc", endorsements=[e]))
    endorser = v.entries[0].endorsers[0]
    assert endorser.name == "Northgate University"
    assert verify_attestation(endorser.proof)               # openable + re-verifiable
    assert endorser.key.encode() == school.public.encode()


def test_works_at_is_endorsed_by_the_named_place():
    me, hospital = kp(1), kp(6)
    e = pf.endorse(hospital, subject=me.public, label="works at", value="Northgate Hospital",
                   endorser_name="Northgate Hospital")
    v = pf.view(pf.make_field(me, "works at", "Northgate Hospital", endorsements=[e]))
    assert v.entries[0].confirmed
    assert v.entries[0].endorsers[0].name == "Northgate Hospital"


def test_forged_endorsement_does_not_count():
    me, school = kp(1), kp(2)
    e = pf.endorse(school, subject=me.public, label="work", value="BSc")
    e.sig = b"\x00" * len(e.sig)             # tampered signature
    v = pf.view(pf.make_field(me, "work", "BSc", endorsements=[e]))
    assert v.entries[0].confirmed is False


def test_endorsement_for_a_different_value_or_label_does_not_attach():
    me, school = kp(1), kp(2)
    wrong_value = pf.endorse(school, subject=me.public, label="work", value="PhD")
    wrong_label = pf.endorse(school, subject=me.public, label="education", value="BSc")
    v = pf.view(pf.make_field(me, "work", "BSc", endorsements=[wrong_value, wrong_label]))
    assert v.entries[0].confirmed is False


def test_add_endorsements_accrue_over_time():
    me, a, b = kp(1), kp(2), kp(3)
    f = pf.make_field(me, "work", "BSc")
    assert pf.view(f).entries[0].confirmed is False
    f = pf.add_endorsements(f, [pf.endorse(a, subject=me.public, label="work", value="BSc")])
    f = pf.add_endorsements(f, [pf.endorse(b, subject=me.public, label="work", value="BSc")])
    assert len(pf.view(f).entries[0].endorsers) == 2
    assert pf.view(f).owner_signed                          # accruing endorsements never breaks the self-sig


def test_custom_profile_rejects_foreign_field():
    me, other = kp(1), kp(5)
    prof = pf.CustomProfile(owner=me.public).with_field(pf.make_field(me, "city", "Rivertown"))
    assert len(prof.fields) == 1
    with pytest.raises(ValueError):
        prof.with_field(pf.make_field(other, "city", "Lakeside"))
