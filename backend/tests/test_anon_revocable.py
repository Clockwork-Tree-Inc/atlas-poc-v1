"""Revocable anonymous credentials: one ZK showing = valid credential AND non-revoked, handle bound."""
from atlas.realid import anon_revocable as arc
from atlas.realid import anon_revocation as rev
from atlas.realid import anon_accreditation as aa


def _setup(claim="work:BSc", handle_seed=b"h-a"):
    issuer = arc.new_issuer()
    reg = rev.RevocationRegistry.new()
    ms = aa.master_secret(b"my-root")
    handle = rev.revocation_handle(handle_seed)
    reg.add_member(handle)
    cred = arc.issue(issuer, claim=claim, master_secret=ms, handle=handle)
    return issuer, reg, ms, handle, cred


def test_valid_credential_and_nonrevoked_verifies():
    issuer, reg, ms, handle, cred = _setup()
    acc = reg.accumulator()
    proof = arc.present(issuer.public, cred, reg.pub, acc, claim="work:BSc",
                        master_secret=ms, handle=handle, witness=reg.witness(handle), nonce=b"n")
    assert arc.verify(issuer.public, reg.pub, acc, proof, claim="work:BSc", nonce=b"n")


def test_revoked_credential_fails():
    issuer, reg, ms, handle, cred = _setup()
    # add a second member so the accumulator is non-trivial after revoking ours
    other = rev.revocation_handle(b"other")
    reg.add_member(other)
    old_witness = reg.witness(handle)
    reg.revoke(handle)
    acc = reg.accumulator()
    proof = arc.present(issuer.public, cred, reg.pub, acc, claim="work:BSc",
                        master_secret=ms, handle=handle, witness=old_witness, nonce=b"n")
    assert not arc.verify(issuer.public, reg.pub, acc, proof, claim="work:BSc", nonce=b"n")


def test_cannot_use_someone_elses_witness_and_handle():
    """The handle is bound to YOUR credential: presenting with a different (valid, non-revoked) handle
    and its witness fails, because the credential signed your handle, not that one."""
    issuer, reg, ms, my_handle, cred = _setup()
    other = rev.revocation_handle(b"other")
    reg.add_member(other)
    acc = reg.accumulator()
    # try to pass using `other`'s handle + witness (both valid in the accumulator) with MY credential
    proof = arc.present(issuer.public, cred, reg.pub, acc, claim="work:BSc",
                        master_secret=ms, handle=other, witness=reg.witness(other), nonce=b"n")
    assert not arc.verify(issuer.public, reg.pub, acc, proof, claim="work:BSc", nonce=b"n")


def test_showings_are_unlinkable():
    issuer, reg, ms, handle, cred = _setup()
    acc = reg.accumulator()
    p1 = arc.present(issuer.public, cred, reg.pub, acc, claim="work:BSc",
                     master_secret=ms, handle=handle, witness=reg.witness(handle), nonce=b"n")
    p2 = arc.present(issuer.public, cred, reg.pub, acc, claim="work:BSc",
                     master_secret=ms, handle=handle, witness=reg.witness(handle), nonce=b"n")
    from atlas.realid.ps_credential import _ser_g1
    assert arc.verify(issuer.public, reg.pub, acc, p1, claim="work:BSc", nonce=b"n")
    assert arc.verify(issuer.public, reg.pub, acc, p2, claim="work:BSc", nonce=b"n")
    assert _ser_g1(p1.s1) != _ser_g1(p2.s1) and _ser_g1(p1.wbar) != _ser_g1(p2.wbar)
    assert p1.c != p2.c


def test_wrong_claim_issuer_or_nonce_fails():
    issuer, reg, ms, handle, cred = _setup()
    other_issuer = arc.new_issuer()
    acc = reg.accumulator()
    proof = arc.present(issuer.public, cred, reg.pub, acc, claim="work:BSc",
                        master_secret=ms, handle=handle, witness=reg.witness(handle), nonce=b"right")
    assert not arc.verify(issuer.public, reg.pub, acc, proof, claim="work:PhD", nonce=b"right")
    assert not arc.verify(other_issuer.public, reg.pub, acc, proof, claim="work:BSc", nonce=b"right")
    assert not arc.verify(issuer.public, reg.pub, acc, proof, claim="work:BSc", nonce=b"wrong")
