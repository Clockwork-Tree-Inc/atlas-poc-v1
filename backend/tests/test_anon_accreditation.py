"""Anonymous credentials on the master secret: ZK showings from any persona, voluntary linking."""
import pytest

from atlas.crypto.sign import keypair_from_seed
from atlas.realid import anon_accreditation as aa
from atlas.realid import ps_credential as ps


def sig_kp(n):
    return keypair_from_seed(bytes([n]) * 32)


def test_issue_present_verify():
    school = aa.new_issuer()
    ms = aa.master_secret(b"my-system-id-root")
    cred = aa.issue(school, claim="work:BSc", master_secret=ms)
    proof = aa.present(school.public, cred, claim="work:BSc", master_secret=ms, nonce=b"n1")
    assert aa.verify(school.public, proof, claim="work:BSc", nonce=b"n1")


def test_two_presentations_are_unlinkable():
    school = aa.new_issuer()
    ms = aa.master_secret(b"root")
    cred = aa.issue(school, claim="work:BSc", master_secret=ms)
    p1 = aa.present(school.public, cred, claim="work:BSc", master_secret=ms, nonce=b"a")
    p2 = aa.present(school.public, cred, claim="work:BSc", master_secret=ms, nonce=b"b")
    assert aa.verify(school.public, p1, claim="work:BSc", nonce=b"a")
    assert aa.verify(school.public, p2, claim="work:BSc", nonce=b"b")
    assert ps._ser_g1(p1.s1) != ps._ser_g1(p2.s1) and p1.challenge != p2.challenge


def test_master_secret_never_leaks():
    school = aa.new_issuer()
    ms = aa.master_secret(b"root")
    cred = aa.issue(school, claim="work:BSc", master_secret=ms)
    proof = aa.present(school.public, cred, claim="work:BSc", master_secret=ms, nonce=b"n")
    assert ms % ps.R not in proof.revealed_vals
    assert ms % ps.R not in proof.responses
    assert (ms % ps.R).to_bytes(32, "big") not in ps.serialize_proof(proof)


def test_display_from_any_persona():
    # all credentials bind to the ONE master secret, so any persona you control shows any of them;
    # the showings are unlinkable, so no one can tell it's the same holder.
    school = aa.new_issuer()
    ms = aa.master_secret(b"root")
    cred = aa.issue(school, claim="work:MSc", master_secret=ms)
    a = aa.present(school.public, cred, claim="work:MSc", master_secret=ms, nonce=b"A")
    b = aa.present(school.public, cred, claim="work:MSc", master_secret=ms, nonce=b"B")
    assert aa.verify(school.public, a, claim="work:MSc", nonce=b"A")
    assert aa.verify(school.public, b, claim="work:MSc", nonce=b"B")


def test_wrong_secret_cannot_present():
    school = aa.new_issuer()
    ms = aa.master_secret(b"root")
    cred = aa.issue(school, claim="work:BSc", master_secret=ms)
    wrong = aa.master_secret(b"someone-elses-root")
    proof = aa.present(school.public, cred, claim="work:BSc", master_secret=wrong, nonce=b"n")
    assert not aa.verify(school.public, proof, claim="work:BSc", nonce=b"n")


def test_verify_is_bound_to_the_claim_and_issuer_and_nonce():
    school, other = aa.new_issuer(), aa.new_issuer()
    ms = aa.master_secret(b"root")
    cred = aa.issue(school, claim="work:BSc", master_secret=ms)
    proof = aa.present(school.public, cred, claim="work:BSc", master_secret=ms, nonce=b"right")
    assert not aa.verify(school.public, proof, claim="work:PhD", nonce=b"right")   # wrong claim
    assert not aa.verify(other.public, proof, claim="work:BSc", nonce=b"right")   # wrong issuer
    assert not aa.verify(school.public, proof, claim="work:BSc", nonce=b"wrong")  # wrong nonce


def test_pseudonym_pickup_no_real_id():
    """A publisher credentials a pen name; no Real-ID anywhere. The pseudonym proves authorship in ZK."""
    publisher = aa.new_issuer()
    ms = aa.master_secret(b"my-root")            # the pen name is one of your personas over your root
    cred = aa.issue(publisher, claim="author:a Novel", master_secret=ms)
    proof = aa.present(publisher.public, cred, claim="author:a Novel", master_secret=ms, nonce=b"n")
    assert aa.verify(publisher.public, proof, claim="author:a Novel", nonce=b"n")


def test_claim_a_credential_under_a_persona_you_choose():
    """Win an award pseudonymously, later claim it under your Real-ID — same credential, your choice."""
    academy = aa.new_issuer()
    ms = aa.master_secret(b"root")
    award = aa.issue(academy, claim="award:LitPrize", master_secret=ms)
    # anonymous showing works
    assert aa.verify(academy.public,
                     aa.present(academy.public, award, claim="award:LitPrize", master_secret=ms, nonce=b"n"),
                     claim="award:LitPrize", nonce=b"n")
    # and you can attach it to a chosen identity when you want the credit
    real_id = sig_kp(1)
    proof, ident, link = aa.present_linked(academy.public, award, claim="award:LitPrize",
                                           master_secret=ms, nonce=b"n", identity=real_id)
    assert ident.encode() == real_id.public.encode()
    assert aa.verify_linked(academy.public, proof, claim="award:LitPrize", nonce=b"n",
                            identity=real_id.public, link_sig=link)


def test_a_linked_claim_cannot_be_hijacked():
    academy = aa.new_issuer()
    ms = aa.master_secret(b"root")
    award = aa.issue(academy, claim="award:LitPrize", master_secret=ms)
    real_id, attacker = sig_kp(1), sig_kp(2)
    proof, _, link = aa.present_linked(academy.public, award, claim="award:LitPrize",
                                       master_secret=ms, nonce=b"n", identity=real_id)
    assert not aa.verify_linked(academy.public, proof, claim="award:LitPrize", nonce=b"n",
                                identity=attacker.public, link_sig=link)


def test_blind_pickup_hides_the_root_from_the_issuer():
    """Pickup exposes only a persona: the issuer blind-signs a commitment and NEVER sees the master
    secret, yet the finalized credential presents and verifies exactly like a normal one."""
    school = aa.new_issuer()
    ms = aa.master_secret(b"my-system-id-root")
    req, blinding = aa.request(school.public, master_secret=ms)   # holder commits, hides the root
    blinded = aa.issue_blind(school, req, claim="work:BSc")       # issuer sees only the claim
    cred = aa.finalize(blinded, blinding)                          # holder unblinds
    proof = aa.present(school.public, cred, claim="work:BSc", master_secret=ms, nonce=b"n")
    assert aa.verify(school.public, proof, claim="work:BSc", nonce=b"n")


def test_blindly_issued_credential_is_bound_to_the_real_master_secret():
    """The unblinded credential is genuinely bound to the committed master secret — a different secret
    can't present it (so the blinding didn't quietly detach it from the root)."""
    school = aa.new_issuer()
    ms = aa.master_secret(b"root")
    req, blinding = aa.request(school.public, master_secret=ms)
    cred = aa.finalize(aa.issue_blind(school, req, claim="work:BSc"), blinding)
    wrong = aa.master_secret(b"different-root")
    bad = aa.present(school.public, cred, claim="work:BSc", master_secret=wrong, nonce=b"n")
    assert not aa.verify(school.public, bad, claim="work:BSc", nonce=b"n")


def test_blind_request_with_a_forged_proof_is_rejected():
    school = aa.new_issuer()
    ms = aa.master_secret(b"root")
    req, _ = aa.request(school.public, master_secret=ms)
    forged = ps.BlindRequest(C=req.C, hidden_idx=req.hidden_idx,
                             proof=(req.proof[0], tuple(0 for _ in req.proof[1])))
    with pytest.raises(ValueError):
        aa.issue_blind(school, forged, claim="work:BSc")
