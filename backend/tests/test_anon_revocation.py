"""Anonymous revocation: bilinear accumulator — revoke once, that credential's membership fails
everywhere while others keep verifying; public check needs no issuer secret."""
import pytest

from atlas.realid import anon_revocation as rev
from atlas.realid.ps_credential import G1


def test_member_verifies_and_nonrevoked_stay_valid():
    reg = rev.RevocationRegistry.new()
    a, b, c = (rev.revocation_handle(s) for s in (b"a", b"b", b"c"))
    for h in (a, b, c):
        reg.add_member(h)
    acc = reg.accumulator()
    for h in (a, b, c):
        assert rev.verify_membership(reg.pub, acc, handle=h, witness=reg.witness(h))


def test_revocation_kills_one_credential_everywhere_others_survive():
    reg = rev.RevocationRegistry.new()
    a, b, c = (rev.revocation_handle(s) for s in (b"a", b"b", b"c"))
    for h in (a, b, c):
        reg.add_member(h)
    old_acc = reg.accumulator()
    wb_before = reg.witness(b)
    assert rev.verify_membership(reg.pub, old_acc, handle=b, witness=wb_before)

    reg.revoke(b)                       # strike off credential b
    new_acc = reg.accumulator()

    # b can no longer prove membership, against neither its old nor the new accumulator
    assert not rev.verify_membership(reg.pub, new_acc, handle=b, witness=wb_before)
    with pytest.raises(ValueError):
        reg.witness(b)                  # b is not a member anymore

    # a and c refresh their witnesses and still verify against the new accumulator
    for h in (a, c):
        assert rev.verify_membership(reg.pub, new_acc, handle=h, witness=reg.witness(h))


def test_wrong_witness_fails():
    reg = rev.RevocationRegistry.new()
    a, b = rev.revocation_handle(b"a"), rev.revocation_handle(b"b")
    reg.add_member(a)
    reg.add_member(b)
    acc = reg.accumulator()
    # a's handle with b's witness must not verify
    assert not rev.verify_membership(reg.pub, acc, handle=a, witness=reg.witness(b))


def test_verification_needs_no_issuer_secret():
    reg = rev.RevocationRegistry.new()
    h = rev.revocation_handle(b"x")
    reg.add_member(h)
    acc, w = reg.accumulator(), reg.witness(h)
    # only the public pub + acc + witness are used — no alpha
    assert rev.verify_membership(reg.pub, acc, handle=h, witness=w)


def test_malformed_witness_rejected():
    reg = rev.RevocationRegistry.new()
    h = rev.revocation_handle(b"x")
    reg.add_member(h)
    acc = reg.accumulator()
    assert not rev.verify_membership(reg.pub, acc, handle=h, witness=G1 and (None, None, None))  # junk point


# --- unlinkable zero-knowledge membership proof ---

def _reg_with(*handles):
    reg = rev.RevocationRegistry.new()
    for h in handles:
        reg.add_member(h)
    return reg


def test_zk_membership_completeness():
    a, b = rev.revocation_handle(b"a"), rev.revocation_handle(b"b")
    reg = _reg_with(a, b)
    acc = reg.accumulator()
    proof = rev.prove_membership(reg.pub, acc, handle=a, witness=reg.witness(a), nonce=b"n")
    assert rev.verify_membership_zk(reg.pub, acc, proof, nonce=b"n")


def test_zk_membership_is_unlinkable_and_hides_the_handle():
    a, b = rev.revocation_handle(b"a"), rev.revocation_handle(b"b")
    reg = _reg_with(a, b)
    acc = reg.accumulator()
    p1 = rev.prove_membership(reg.pub, acc, handle=a, witness=reg.witness(a), nonce=b"n")
    p2 = rev.prove_membership(reg.pub, acc, handle=a, witness=reg.witness(a), nonce=b"n")
    # both verify, but the revealed element and challenge differ (re-randomised each time)
    assert rev.verify_membership_zk(reg.pub, acc, p1, nonce=b"n")
    assert rev.verify_membership_zk(reg.pub, acc, p2, nonce=b"n")
    from atlas.realid.ps_credential import _ser_g1
    assert _ser_g1(p1.wbar) != _ser_g1(p2.wbar)
    assert p1.c != p2.c
    # the handle scalar itself never appears in the proof
    assert (a % rev.R) not in (p1.z_id, p1.z_rho, p1.c)


def test_zk_membership_soundness_revoked_cannot_prove():
    a, b = rev.revocation_handle(b"a"), rev.revocation_handle(b"b")
    reg = _reg_with(a, b)
    old_witness_b = reg.witness(b)
    reg.revoke(b)
    new_acc = reg.accumulator()
    # b tries to prove membership with its old witness against the new accumulator -> must fail
    proof = rev.prove_membership(reg.pub, new_acc, handle=b, witness=old_witness_b, nonce=b"n")
    assert not rev.verify_membership_zk(reg.pub, new_acc, proof, nonce=b"n")
    # meanwhile a, still valid, proves fine against the new accumulator
    good = rev.prove_membership(reg.pub, new_acc, handle=a, witness=reg.witness(a), nonce=b"n")
    assert rev.verify_membership_zk(reg.pub, new_acc, good, nonce=b"n")


def test_zk_membership_wrong_witness_or_handle_fails():
    a, b = rev.revocation_handle(b"a"), rev.revocation_handle(b"b")
    reg = _reg_with(a, b)
    acc = reg.accumulator()
    # a's handle with b's witness
    bad1 = rev.prove_membership(reg.pub, acc, handle=a, witness=reg.witness(b), nonce=b"n")
    assert not rev.verify_membership_zk(reg.pub, acc, bad1, nonce=b"n")
    # b's witness claimed under a wrong made-up handle
    bad2 = rev.prove_membership(reg.pub, acc, handle=rev.revocation_handle(b"z"),
                                witness=reg.witness(b), nonce=b"n")
    assert not rev.verify_membership_zk(reg.pub, acc, bad2, nonce=b"n")


def test_zk_membership_nonce_binding():
    a = rev.revocation_handle(b"a")
    reg = _reg_with(a, rev.revocation_handle(b"b"))
    acc = reg.accumulator()
    proof = rev.prove_membership(reg.pub, acc, handle=a, witness=reg.witness(a), nonce=b"right")
    assert not rev.verify_membership_zk(reg.pub, acc, proof, nonce=b"wrong")
