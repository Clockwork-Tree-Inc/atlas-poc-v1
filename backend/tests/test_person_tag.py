"""ZK person-tag: the nullifier is bound (in zero-knowledge) to the SAME hidden root the credential
commits to — the host never sees the root, can't be fooled by a mismatched/forged tag, and the
proof is fresh (no replay). Plus the tag's uniqueness/unlinkability properties."""

import os

from dataclasses import replace

from atlas.zk.person_tag import (PersonTagProof, commit_root, nullifier, prove_person_tag,
                                 root_scalar, verify_person_tag)


def _fresh():
    return 7, os.urandom(16)          # (epoch, verifier nonce)


def test_honest_proof_verifies_and_reveals_only_the_tag():
    x = root_scalar(os.urandom(32))
    C, s = commit_root(x)
    epoch, nonce = _fresh()
    pf = prove_person_tag(x, s, C, b"room-1", epoch=epoch, nonce=nonce)
    assert verify_person_tag(pf, expected_epoch=epoch, expected_nonce=nonce)
    assert pf.N == nullifier(x, b"room-1")            # the revealed tag is the VRF nullifier
    # the proof object carries no root and no blinding — only C, N, and the DLEQ terms
    assert not hasattr(pf, "x") and not hasattr(pf, "s")


def test_binding_cannot_present_valid_C_with_a_mismatched_nullifier():
    x = root_scalar(os.urandom(32))
    C, s = commit_root(x)
    epoch, nonce = _fresh()
    pf = prove_person_tag(x, s, C, b"room-1", epoch=epoch, nonce=nonce)
    # swap in a nullifier for a DIFFERENT root (e.g. to dodge a block / fake a fresh identity)
    other = root_scalar(os.urandom(32))
    forged = replace(pf, N=nullifier(other, b"room-1"))
    assert not verify_person_tag(forged, expected_epoch=epoch, expected_nonce=nonce)
    # tampering C likewise fails
    C2, _ = commit_root(other)
    assert not verify_person_tag(replace(pf, C=C2), expected_epoch=epoch, expected_nonce=nonce)


def test_replay_rejected_wrong_epoch_or_nonce():
    x = root_scalar(os.urandom(32))
    C, s = commit_root(x)
    epoch, nonce = _fresh()
    pf = prove_person_tag(x, s, C, b"room-1", epoch=epoch, nonce=nonce)
    assert not verify_person_tag(pf, expected_epoch=epoch + 1, expected_nonce=nonce)   # stale epoch
    assert not verify_person_tag(pf, expected_epoch=epoch, expected_nonce=os.urandom(16))  # replayed


def test_tag_is_unique_per_person_per_scope_and_unlinkable_across_scopes():
    root = os.urandom(32)
    x = root_scalar(root)
    # one-person-one-account: same root + same scope -> identical tag (a "new pseudonym" is the same N)
    assert nullifier(x, b"room-1") == nullifier(root_scalar(root), b"room-1")
    # unlinkable across scopes: same person, different scope -> unrelated tag
    assert nullifier(x, b"room-1") != nullifier(x, b"room-2")
    # different person -> different tag
    assert nullifier(x, b"room-1") != nullifier(root_scalar(os.urandom(32)), b"room-1")
