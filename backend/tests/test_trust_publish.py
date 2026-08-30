"""Self-published accreditation bundles: build, serve, fetch, verify, and fold into a TrustGraph."""
import pytest

from atlas.crypto.sign import keypair_from_seed
from atlas import trust_graph as tg
from atlas.interop import trust_publish as tp


def kp(n):
    return keypair_from_seed(bytes([n]) * 32)


def test_org_publishes_its_own_accreditation_and_a_verifier_loads_it():
    gov, board, uni = kp(1), kp(2), kp(3)
    # the accreditor authorized the board (published on the accreditor's own domain)
    auth = tg.authorize(gov, grantee=board.public, remit=tg.ACCREDITOR, grantor_name="DoE")
    acc = tg.accredit(board, org=uni.public, kind="university", authority_name="Board")

    board_bundle = tp.build_trust_bundle(publisher=board, domain="board.example",
                                         edges=[auth, acc])   # board holds `auth`, issues `acc`
    uni_bundle = tp.build_trust_bundle(publisher=uni, domain="uni.example", edges=[acc])  # uni holds acc

    served = {tp.trust_bundle_url("board.example"): board_bundle.to_json(),
              tp.trust_bundle_url("uni.example"): uni_bundle.to_json()}

    g = tg.TrustGraph(trusted_roots={gov.public.encode()}, now=10)
    tp.fetch_and_load(g, "board.example", fetch=lambda u: served[u])
    tp.fetch_and_load(g, "uni.example", fetch=lambda u: served[u])

    assert g.verify_org(uni.public, kind="university") is not None


def test_bundle_round_trips_through_json():
    gov, board = kp(1), kp(2)
    auth = tg.authorize(gov, grantee=board.public, remit=tg.ACCREDITOR)
    b = tp.build_trust_bundle(publisher=board, domain="board.example", edges=[auth])
    again = tp.parse_trust_bundle(b.to_json())
    assert tp.verify_trust_bundle(again)
    assert again.domain == "board.example"
    assert again.edges[0].claim == auth.claim
    assert again.publisher.encode() == board.public.encode()


def test_tampered_bundle_fails_verification():
    gov, board = kp(1), kp(2)
    auth = tg.authorize(gov, grantee=board.public, remit=tg.ACCREDITOR)
    b = tp.build_trust_bundle(publisher=board, domain="board.example", edges=[auth])
    d = tp.parse_trust_bundle(b.to_json())
    d.domain = "evil.example"       # move the same edges under a different domain
    assert not tp.verify_trust_bundle(d)


def test_publisher_cannot_bundle_edges_that_are_not_about_it():
    gov, board, other = kp(1), kp(2), kp(9)
    # an accreditation about SOMEONE ELSE, not involving `other`
    acc = tg.accredit(board, org=kp(3).public, kind="university")
    with pytest.raises(tp.TrustPublishError):
        tp.build_trust_bundle(publisher=other, domain="other.example", edges=[acc])


def test_forged_edge_in_bundle_rejected():
    gov, board, uni = kp(1), kp(2), kp(3)
    acc = tg.accredit(board, org=uni.public, kind="university")
    acc.sig = b"\x00" * len(acc.sig)
    with pytest.raises(tp.TrustPublishError):
        tp.build_trust_bundle(publisher=board, domain="board.example", edges=[acc])
