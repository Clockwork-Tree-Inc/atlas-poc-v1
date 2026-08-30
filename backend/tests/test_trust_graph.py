"""Trust graph: orgs verified by the appropriate authority (chaining to a consumer-trusted root),
people bound to real-world identity, downstream accreditation, cross-recognition, and duplicate-
registration detection."""
import pytest

from atlas.crypto.sign import keypair_from_seed
from atlas import trust_graph as tg


def kp(n):
    return keypair_from_seed(bytes([n]) * 32)


def graph(*roots, now=10):
    return tg.TrustGraph(trusted_roots={r.public.encode() for r in roots}, now=now)


def test_accreditor_authorized_by_root_verifies_org():
    gov, board, uni = kp(1), kp(2), kp(3)
    g = graph(gov)
    g.add(tg.authorize(gov, grantee=board.public, remit=tg.ACCREDITOR, grantor_name="DoE"))
    g.add(tg.accredit(board, org=uni.public, kind="university", authority_name="Regional Board"))
    path = g.verify_org(uni.public, kind="university")
    assert path is not None
    assert path.authorities() == ("DoE", "Regional Board")   # walked root-first


def test_unauthorized_accreditor_does_not_verify_org():
    gov, imposter, uni = kp(1), kp(2), kp(3)
    g = graph(gov)
    # imposter was never authorized by the root
    g.add(tg.accredit(imposter, org=uni.public, kind="university", authority_name="Totally Legit Board"))
    assert g.verify_org(uni.public) is None


def test_downstream_accreditation_flows_through_multiple_hops():
    gov, national, regional, uni = kp(1), kp(2), kp(3), kp(4)
    g = graph(gov)
    g.add(tg.authorize(gov, grantee=national.public, remit=tg.ACCREDITOR))
    g.add(tg.authorize(national, grantee=regional.public, remit=tg.ACCREDITOR))
    g.add(tg.accredit(regional, org=uni.public, kind="university"))
    assert g.verify_org(uni.public) is not None
    # but a body that only holds a DIFFERENT remit cannot accredit
    registry = kp(5)
    g.add(tg.authorize(gov, grantee=registry.public, remit=tg.REGISTRY))
    other = kp(6)
    g.add(tg.accredit(registry, org=other.public, kind="university"))
    assert g.verify_org(other.public) is None


def test_person_bound_to_real_world_identity():
    verifier, alice = kp(1), kp(7)
    g = graph()   # no accreditation roots needed for eID
    g.add(tg.bind_real_identity(verifier, person=alice.public, verifier_name="eID"))
    assert g.has_real_identity(alice.public, trusted_verifier_keys={verifier.public.encode()})
    assert not g.has_real_identity(alice.public, trusted_verifier_keys={kp(99).public.encode()})


def test_accredited_school_certifies_its_graduate():
    gov, board, uni, doctor = kp(1), kp(2), kp(3), kp(8)
    g = graph(gov)
    g.add(tg.authorize(gov, grantee=board.public, remit=tg.ACCREDITOR))
    g.add(tg.accredit(board, org=uni.public, kind="university"))
    g.add(tg.certify(uni, person=doctor.public, qualification="md", issuer_name="Central College"))
    assert g.verify_qualification(doctor.public, "md") is not None
    # a certificate from an UNVERIFIED "school" does not count
    fake = kp(50)
    quack = kp(51)
    g.add(tg.certify(fake, person=quack.public, qualification="md"))
    assert g.verify_qualification(quack.public, "md") is None


def test_licensor_can_certify_a_person_directly():
    gov, medboard, doctor = kp(1), kp(2), kp(8)
    g = graph(gov)
    g.add(tg.authorize(gov, grantee=medboard.public, remit=tg.LICENSOR))
    g.add(tg.certify(medboard, person=doctor.public, qualification="md", issuer_name="Medical Council"))
    assert g.verify_qualification(doctor.public, "md") is not None


def test_cross_recognition_across_two_roots():
    # A verifier that trusts BOTH national roots recognizes a doctor accredited under EITHER.
    us_gov, uk_gov = kp(1), kp(10)
    us_board, uk_board = kp(2), kp(11)
    us_uni, uk_uni = kp(3), kp(12)
    us_doc, uk_doc = kp(8), kp(13)
    g = graph(us_gov, uk_gov)
    for gov, board, uni, doc in [(us_gov, us_board, us_uni, us_doc), (uk_gov, uk_board, uk_uni, uk_doc)]:
        g.add(tg.authorize(gov, grantee=board.public, remit=tg.ACCREDITOR))
        g.add(tg.accredit(board, org=uni.public, kind="university"))
        g.add(tg.certify(uni, person=doc.public, qualification="md"))
    assert g.verify_qualification(us_doc.public, "md") is not None
    assert g.verify_qualification(uk_doc.public, "md") is not None


def test_affiliation_requires_a_verified_org():
    gov, board, uni, registrar = kp(1), kp(2), kp(3), kp(9)
    g = graph(gov)
    # before the org is verified, its affiliation edge does not stand
    g.add(tg.affiliate(uni, person=registrar.public, role="registrar", org_name="Central College"))
    assert g.verify_affiliation(registrar.public, uni.public, "registrar") is None
    # verify the org, and the affiliation now stands
    g.add(tg.authorize(gov, grantee=board.public, remit=tg.ACCREDITOR))
    g.add(tg.accredit(board, org=uni.public, kind="university"))
    assert g.verify_affiliation(registrar.public, uni.public, "registrar") is not None


def test_registration_by_number_and_duplicate_detection():
    gov, registry, mine, imposter = kp(1), kp(2), kp(3), kp(4)
    g = graph(gov)
    g.add(tg.authorize(gov, grantee=registry.public, remit=tg.REGISTRY))
    g.add(tg.register(registry, org=mine.public, number="OC-12345", registry_name="Companies House"))
    assert g.verify_org(mine.public) is not None
    assert g.sole_registrant(mine.public, "OC-12345")
    assert not g.registration_conflict("OC-12345")
    # someone tries to register MY number to their key -> visible as a conflict
    g.add(tg.register(registry, org=imposter.public, number="OC-12345"))
    assert g.registration_conflict("OC-12345")
    assert not g.sole_registrant(mine.public, "OC-12345")


def test_revocation_forward_effective():
    gov, board, uni = kp(1), kp(2), kp(3)
    g = graph(gov)
    g.add(tg.authorize(gov, grantee=board.public, remit=tg.ACCREDITOR))
    acc = tg.accredit(board, org=uni.public, kind="university")
    g.add(acc)
    assert g.verify_org(uni.public) is not None
    g.revoke(acc)                      # struck off
    assert g.verify_org(uni.public) is None


def test_forged_edge_rejected_at_add():
    gov, board, uni = kp(1), kp(2), kp(3)
    g = graph(gov)
    acc = tg.accredit(board, org=uni.public, kind="university")
    acc.sig = b"\x00" * len(acc.sig)   # tamper
    with pytest.raises(tg.TrustGraphError):
        g.add(acc)


def test_future_dated_edge_not_yet_live():
    gov, board, uni = kp(1), kp(2), kp(3)
    g = graph(gov, now=5)
    g.add(tg.authorize(gov, grantee=board.public, remit=tg.ACCREDITOR, epoch=1))
    g.add(tg.accredit(board, org=uni.public, kind="university", epoch=9))   # issued in the future
    assert g.verify_org(uni.public) is None
    g.now = 10
    assert g.verify_org(uni.public) is not None
