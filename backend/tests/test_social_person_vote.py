"""Sybil-resistant voting via the ZK person-tag: one HUMAN = one vote per target, regardless of how
many personas the human votes through; distinct humans count distinctly; unlinkable across targets;
the root is never seen and a stale proof is rejected."""

import os

import pytest

from atlas.crypto.sign import generate_sig_keypair
from atlas.spaces.social import cast_vote_proof, tally
from atlas.zk.person_tag import commit_root, prove_person_tag, root_scalar


def _proof(root: bytes, target: bytes, epoch: int, nonce: bytes):
    """The voter's ZK person-tag proof for scope = the item (target) being voted on."""
    x = root_scalar(root)
    C, s = commit_root(x)
    return prove_person_tag(x, s, C, target, epoch=epoch, nonce=nonce)


def test_one_human_one_vote_regardless_of_persona():
    target = os.urandom(32)
    person = os.urandom(32)
    e1, n1 = 1, os.urandom(16)
    e2, n2 = 2, os.urandom(16)
    # the SAME human votes through TWO different personas (two signing keypairs), each with a fresh proof
    v1 = cast_vote_proof(generate_sig_keypair(), _proof(person, target, e1, n1), up=True, epoch=e1, nonce=n1)
    v2 = cast_vote_proof(generate_sig_keypair(), _proof(person, target, e2, n2), up=False, epoch=e2, nonce=n2)
    assert v1.nullifier == v2.nullifier              # same person -> same person-tag N -> ONE human
    score = tally(target=target, votes=[v1, v2])
    assert score.likes + score.dislikes == 1         # counts as a single human (last vote wins)
    assert score.dislikes == 1

    # a DIFFERENT human is a distinct vote
    person2 = os.urandom(32)
    e3, n3 = 3, os.urandom(16)
    v3 = cast_vote_proof(generate_sig_keypair(), _proof(person2, target, e3, n3), up=True, epoch=e3, nonce=n3)
    s2 = tally(target=target, votes=[v1, v2, v3])
    assert s2.likes == 1 and s2.dislikes == 1        # two humans, two votes

    # same human, DIFFERENT target -> different tag (unlinkable across items)
    other = os.urandom(32)
    e4, n4 = 4, os.urandom(16)
    v4 = cast_vote_proof(generate_sig_keypair(), _proof(person, other, e4, n4), up=True, epoch=e4, nonce=n4)
    assert v4.nullifier != v1.nullifier


def test_stale_or_invalid_proof_is_rejected():
    target = os.urandom(32)
    p = _proof(os.urandom(32), target, 1, os.urandom(16))
    with pytest.raises(ValueError):
        cast_vote_proof(generate_sig_keypair(), p, up=True, epoch=2, nonce=os.urandom(16))  # wrong epoch/nonce
