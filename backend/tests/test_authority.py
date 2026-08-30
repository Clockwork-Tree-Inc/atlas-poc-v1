"""Adversarial pressure-test for the authority engine (AUTHORITY_MODEL §4).

Each attack A1–A16 is a test that MUST fail closed. Hand-crafted malicious chains bypass the
`delegate()` creation guards to prove `verify_chain` itself catches every escalation — verification
is the trust boundary, not the constructor. A13–A16 (the boundary findings from independent review:
rotation-as-compromise-recovery, bearer proof-of-possession, authenticated revocation, unknown-caveat
fail-closed) are included. Plus happy-path delegation, root rotation, and revocation-subtree tests.
"""

import pytest

from atlas.crypto.sign import keypair_from_seed, sign
from atlas.authority import (
    ACCOUNTABLE, ROOT, AuthorityError, Caveat, Grant, RightSet, Revocation, RotationCert,
    delegate, issue, issue_fs, revoke, verify_access, verify_chain,
)
from atlas.authority.fs_sign import fs_keygen, _leaf_seed, _auth_path

RES = b"space-1"
# ladder levels for a Space
NONE, READ, POST, ADMIN, OWNER = 0, 1, 2, 3, 4


def kp(n: int):
    return keypair_from_seed(bytes([n]) * 32)


ROOTKP = kp(1)          # the resource root (Space owner)
A, B, C, X = kp(2), kp(3), kp(4), kp(9)   # principals; X = attacker


def _signed(signer, *, grantor=None, grantee, rights, caveats=(), depth=0, parent, epoch=0,
            resource=RES) -> Grant:
    """Build + sign a grant by hand (for crafting malicious chains)."""
    g = Grant(grantor=grantor or signer.public, grantee=grantee, resource=resource, rights=rights,
              caveats=frozenset(caveats), delegable_depth=depth, parent=parent, epoch=epoch)
    g.sig = sign(signer, g._body())
    return g


def _ok(chain, now=1000, **kw):
    return verify_chain(chain, resource=RES, resource_root=ROOTKP.public, now=now, **kw)


# --------------------------------------------------------------------------- happy path
def test_happy_delegation_chain():
    g0 = issue(ROOTKP, grantee=A.public, resource=RES, rights=RightSet(ADMIN), delegable_depth=2)
    g1 = delegate(g0, A, grantee=B.public, rights=RightSet(POST))
    g2 = delegate(g1, B, grantee=C.public, rights=RightSet(READ))
    assert _ok([g0, g1, g2]) == RightSet(READ)           # leaf's effective rights


def test_flags_attenuate_too():
    g0 = issue(ROOTKP, grantee=A.public, resource=RES,
               rights=RightSet(POST, frozenset({"invite", "pin"})), delegable_depth=1)
    g1 = delegate(g0, A, grantee=B.public, rights=RightSet(POST, frozenset({"invite"})))
    assert _ok([g0, g1]) == RightSet(POST, frozenset({"invite"}))
    with pytest.raises(AuthorityError):                  # can't ADD a flag the parent lacked
        delegate(g0, A, grantee=B.public, rights=RightSet(POST, frozenset({"invite", "ban"})))


# --------------------------------------------------------------------------- A1 / A2 escalation
def test_A1_escalate_rights_on_delegate_rejected_at_verify():
    g0 = issue(ROOTKP, grantee=A.public, resource=RES, rights=RightSet(POST), delegable_depth=2)
    evil = _signed(A, grantee=B.public, rights=RightSet(ADMIN), depth=1, parent=g0.grant_id())
    with pytest.raises(AuthorityError, match="escalate"):
        _ok([g0, evil])


def test_A2_confused_deputy_capped_by_held_rights():
    g0 = issue(ROOTKP, grantee=A.public, resource=RES, rights=RightSet(READ), delegable_depth=2)
    evil = _signed(A, grantee=B.public, rights=RightSet(ADMIN), depth=1, parent=g0.grant_id())
    with pytest.raises(AuthorityError, match="escalate"):
        _ok([g0, evil])


# --------------------------------------------------------------------------- A3 forgery
def test_A3_tampered_grant_fails_signature():
    g0 = issue(ROOTKP, grantee=A.public, resource=RES, rights=RightSet(READ))
    g0.rights = RightSet(OWNER)                          # tamper AFTER signing
    with pytest.raises(AuthorityError, match="signature"):
        _ok([g0])


def test_A3_wrong_signer_fails():
    evil = _signed(X, grantee=A.public, rights=RightSet(OWNER), parent=ROOT)
    with pytest.raises(AuthorityError, match="resource root"):
        _ok([evil])


# --------------------------------------------------------------------------- A4 re-delegate non-delegable
def test_A4_redelegate_nondelegable_rejected_at_creation_and_verify():
    g0 = issue(ROOTKP, grantee=A.public, resource=RES, rights=RightSet(POST), delegable_depth=0)
    with pytest.raises(AuthorityError, match="not delegable"):
        delegate(g0, A, grantee=B.public, rights=RightSet(READ))
    evil = _signed(A, grantee=B.public, rights=RightSet(READ), depth=0, parent=g0.grant_id())
    with pytest.raises(AuthorityError, match="not delegable"):
        _ok([g0, evil])


# --------------------------------------------------------------------------- A5 / A12 root impersonation
def test_A5_A12_root_must_be_the_resource_root():
    evil = _signed(X, grantee=A.public, rights=RightSet(OWNER), parent=ROOT)
    with pytest.raises(AuthorityError, match="resource root"):
        _ok([evil])


# --------------------------------------------------------------------------- A6 chain splicing
def test_A6_splice_onto_richer_parent_rejected():
    rich = issue(ROOTKP, grantee=A.public, resource=RES, rights=RightSet(ADMIN), delegable_depth=2)
    poor = issue(ROOTKP, grantee=A.public, resource=RES, rights=RightSet(READ), delegable_depth=2)
    child = delegate(poor, A, grantee=B.public, rights=RightSet(READ))
    with pytest.raises(AuthorityError, match="parent hash mismatch"):
        _ok([rich, child])


def test_A6_continuity_grantor_must_be_parent_grantee():
    g0 = issue(ROOTKP, grantee=A.public, resource=RES, rights=RightSet(POST), delegable_depth=2)
    evil = _signed(X, grantee=B.public, rights=RightSet(READ), depth=1, parent=g0.grant_id())
    with pytest.raises(AuthorityError, match="not the parent's grantee"):
        _ok([g0, evil])


# --------------------------------------------------------------------------- A7 expiry
def test_A7_expired_grant_rejected():
    g0 = issue(ROOTKP, grantee=A.public, resource=RES, rights=RightSet(READ),
               caveats=[Caveat("expiry", "100")])
    _ok([g0], now=50)                                    # still valid
    with pytest.raises(AuthorityError, match="expired"):
        _ok([g0], now=101)


# --------------------------------------------------------------------------- A8 / A15 revocation
def test_A8_revoked_ancestor_kills_subtree():
    g0 = issue(ROOTKP, grantee=A.public, resource=RES, rights=RightSet(ADMIN), delegable_depth=2)
    g1 = delegate(g0, A, grantee=B.public, rights=RightSet(POST))
    _ok([g0, g1])                                        # fine before revocation
    with pytest.raises(AuthorityError, match="revoked"):
        _ok([g0, g1], revocations=[revoke(g0, ROOTKP)])  # root revokes the PARENT -> subtree dies


def test_A15_unauthorized_revocation_ignored():
    g0 = issue(ROOTKP, grantee=A.public, resource=RES, rights=RightSet(ADMIN), delegable_depth=1)
    g1 = delegate(g0, A, grantee=B.public, rights=RightSet(READ))
    # X (a stranger, not grantor/ancestor) tries to revoke g1 -> IGNORED (no revoke-as-DoS)
    assert _ok([g0, g1], revocations=[revoke(g1, X)]) == RightSet(READ)
    # A legitimate revoker on the authority line (root, or A) revoking g1 -> honored
    with pytest.raises(AuthorityError, match="revoked"):
        _ok([g0, g1], revocations=[revoke(g1, ROOTKP)])
    with pytest.raises(AuthorityError, match="revoked"):
        _ok([g0, g1], revocations=[revoke(g1, A)])


# --------------------------------------------------------------------------- A9 personhood
def test_A9_accountable_right_requires_verified_human():
    g0 = issue(ROOTKP, grantee=A.public, resource=RES,
               rights=RightSet(ADMIN, frozenset({ACCOUNTABLE})))
    verified = {A.public.encode()}
    _ok([g0], is_verified_human=lambda p: p.encode() in verified)      # A verified -> ok
    with pytest.raises(AuthorityError, match="unverified"):
        _ok([g0], is_verified_human=lambda p: False)
    with pytest.raises(AuthorityError, match="unverified"):
        _ok([g0])                                                      # no predicate -> fail closed


# --------------------------------------------------------------------------- A10 caveat drop
def test_A10_dropping_a_caveat_rejected():
    g0 = issue(ROOTKP, grantee=A.public, resource=RES, rights=RightSet(POST),
               caveats=[Caveat("channel", "general")], delegable_depth=2)
    evil = _signed(A, grantee=B.public, rights=RightSet(POST), caveats=[], depth=1,
                   parent=g0.grant_id())
    with pytest.raises(AuthorityError, match="caveats were dropped"):
        _ok([g0, evil], understood_caveats=frozenset({"channel"}))


# --------------------------------------------------------------------------- A11 unambiguous encoding
def test_A11_encoding_is_field_injective():
    base = issue(ROOTKP, grantee=A.public, resource=RES, rights=RightSet(READ))
    alt_res = _signed(ROOTKP, grantee=A.public, rights=RightSet(READ), parent=ROOT, resource=b"space-2")
    alt_rights = _signed(ROOTKP, grantee=A.public, rights=RightSet(POST), parent=ROOT)
    alt_grantee = _signed(ROOTKP, grantee=B.public, rights=RightSet(READ), parent=ROOT)
    ids = {base.grant_id(), alt_res.grant_id(), alt_rights.grant_id(), alt_grantee.grant_id()}
    assert len(ids) == 4


# --------------------------------------------------------------------------- A13 (OPEN — safe interim)
def test_A13_rotated_out_root_is_retired_including_backdating():
    # A13 was NOT actually defeated by the epoch-cutoff check: `epoch` is a self-asserted signed field,
    # so a compromised old key set epoch<=cutoff and BACKDATED a fresh grant (confirmed by PoC). Safe
    # interim: a rotated-out root is RETIRED — NONE of its grants verify, including the backdating
    # attack (epoch == cutoff). The real structural fix is a forward-secure ratcheted root signer
    # (AUTHORITY_MODEL A13); until then, re-issue live grants under the new root.
    newroot = kp(20)
    cert = RotationCert(resource=RES, old_root=ROOTKP.public, new_root=newroot.public, epoch=100)
    cert.sig = sign(ROOTKP, cert._body())
    for epoch in (3, 100, 500):     # pre-cut, AT-cut (the backdating attack), post-cut — ALL rejected
        g = issue(ROOTKP, grantee=X.public, resource=RES, rights=RightSet(OWNER), epoch=epoch)
        with pytest.raises(AuthorityError, match="rotated out"):
            verify_chain([g], resource=RES, resource_root=newroot.public, now=500, rotations=[cert])


def test_forged_rotation_cert_ignored():
    newroot = kp(20)
    g0 = issue(ROOTKP, grantee=A.public, resource=RES, rights=RightSet(READ))
    forged = RotationCert(resource=RES, old_root=ROOTKP.public, new_root=newroot.public, epoch=1)
    forged.sig = sign(X, forged._body())                 # signed by X, NOT the old root
    with pytest.raises(AuthorityError, match="resource root"):
        verify_chain([g0], resource=RES, resource_root=newroot.public, now=1000, rotations=[forged])


# --------------------------------------------------------------------------- A14 bearer / proof-of-possession
def test_A14_chain_needs_proof_of_possession():
    g0 = issue(ROOTKP, grantee=A.public, resource=RES, rights=RightSet(READ))
    challenge = b"fresh-single-use-nonce"
    good = sign(A, challenge)                            # A holds the grantee key
    assert verify_access([g0], challenge=challenge, proof=good, now=1000,
                         resource=RES, resource_root=ROOTKP.public) == RightSet(READ)
    # an attacker who read the chain off the public ledger but lacks A's key cannot present it
    bad = sign(X, challenge)
    with pytest.raises(AuthorityError, match="possession"):
        verify_access([g0], challenge=challenge, proof=bad, now=1000,
                      resource=RES, resource_root=ROOTKP.public)


# --------------------------------------------------------------------------- A16 unknown caveat fails closed
def test_A16_unrecognized_caveat_fails_closed():
    g0 = issue(ROOTKP, grantee=A.public, resource=RES, rights=RightSet(READ),
               caveats=[Caveat("geo-fence", "EU")])
    with pytest.raises(AuthorityError, match="unrecognized caveat"):
        _ok([g0])                                        # verifier doesn't understand geo-fence -> deny
    assert _ok([g0], understood_caveats=frozenset({"geo-fence"})) == RightSet(READ)


# --------------------------------------------------------------------------- minor: now is required
def test_now_is_required_no_fail_open_expiry():
    g0 = issue(ROOTKP, grantee=A.public, resource=RES, rights=RightSet(READ))
    with pytest.raises(TypeError):
        verify_chain([g0], resource=RES, resource_root=ROOTKP.public)   # `now` omitted


# ------------------------------------------------------ A13 FIX: forward-secure ratcheted root
def test_fs_root_happy_and_delegation():
    pub, signer = fs_keygen(bytes(range(32)), height=3)
    g0 = issue_fs(signer, grantee=A.public, resource=RES, rights=RightSet(ADMIN), delegable_depth=1)
    assert verify_chain([g0], resource=RES, resource_root=pub, now=1000) == RightSet(ADMIN)
    g1 = delegate(g0, A, grantee=B.public, rights=RightSet(READ))     # delegate off an FS-root grant
    assert verify_chain([g0, g1], resource=RES, resource_root=pub, now=1000) == RightSet(READ)


def test_A13_fs_root_kills_backdating():
    # THE A13 fix, end to end: a compromised current signer cannot backdate a root grant, because the
    # signing leaf's epoch is INTRINSIC to its Merkle position — a past leaf's secret is unrecoverable.
    from atlas.crypto.sign import keypair_from_seed, sign as _sign
    pub, signer = fs_keygen(bytes(range(32)), height=3)
    signer.sign(b"warm")                                              # honest activity at epoch 0
    for _ in range(3):
        signer.advance()                                             # COMPROMISE point: attacker holds state_3
    leaf3 = keypair_from_seed(_leaf_seed(signer._state))              # the only leaf secret they have
    # forge a root grant CLAIMING epoch 0 (with epoch-0's public auth path), signed by leaf 3:
    forged = Grant(grantor=leaf3.public, grantee=X.public, resource=RES, rights=RightSet(OWNER),
                   caveats=frozenset(), delegable_depth=0, parent=ROOT, epoch=0)
    forged.sig = _sign(leaf3, forged._body())
    forged.fs_epoch = 0
    forged.fs_auth_path = _auth_path(signer._levels, 0)
    with pytest.raises(AuthorityError, match="not in the FS root tree"):
        verify_chain([forged], resource=RES, resource_root=pub, now=1000)
    # the compromise CAN still sign at the current epoch (forward-secure protects the past, not future)
    g_now = issue_fs(signer, grantee=X.public, resource=RES, rights=RightSet(READ))
    assert verify_chain([g_now], resource=RES, resource_root=pub, now=1000) == RightSet(READ)
