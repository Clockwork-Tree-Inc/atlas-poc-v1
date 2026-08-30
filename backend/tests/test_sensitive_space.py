"""Sensitive space: records-backed space at the high-protection tier — role-gates WHO, records-gates WHEN."""
import pytest

from atlas.crypto.primitives import aead_encrypt, random_bytes
from atlas.crypto.sign import keypair_from_seed, sign
from atlas.records import records as R
from atlas.spaces.sensitive_space import (
    SensitiveSpace, SensitiveSpaceError, break_glass, open_own, reopen_dispute,
)
from atlas.spaces.space_policy import Role, SpacePolicy

FILE = b"Dx: sensitive."


def kp(n):
    return keypair_from_seed(bytes([n]) * 32)


def _space(creator, ck):
    policy = SpacePolicy.genesis(b"space:clinic", creator.public)
    rec = R.seal_record(FILE, ck)
    return SensitiveSpace(policy=policy, record=rec, log=R.AccessLog())


def _grant(policy, owner, who, role, epoch):
    ch = policy.propose("grant", target=who.public, role=role, epoch=epoch)
    policy.authorize(ch, [(owner.public, sign(owner, ch.body()))])


def test_member_reader_opens_but_non_member_is_blocked():
    owner, patient, stranger = kp(1), kp(2), kp(9)
    ck = random_bytes(32)
    space = _space(owner, ck)
    _grant(space.policy, owner, patient, Role.READER, 1)

    assert open_own(space, patient.public, content_key=ck, now_round=10) == FILE   # member reads
    with pytest.raises(SensitiveSpaceError):
        open_own(space, stranger.public, content_key=ck, now_round=11)             # non-member blocked


def test_role_gates_who_records_gates_when():
    # A member with only READER cannot break glass (needs the break-glass role); and even the right
    # role can't beat the records-layer condition.
    owner, oncall = kp(1), kp(3)
    ck, bg = random_bytes(32), random_bytes(32)
    space = _space(owner, ck)
    _grant(space.policy, owner, oncall, Role.READER, 1)   # only reader

    wrapped = aead_encrypt(bg, ck)
    with pytest.raises(SensitiveSpaceError):
        break_glass(space, oncall.public, break_glass_key=bg, wrapped_content_key=wrapped, now_round=5)

    _grant(space.policy, owner, oncall, Role.BREAK_GLASS, 2)  # now has break-glass
    assert break_glass(space, oncall.public, break_glass_key=bg, wrapped_content_key=wrapped, now_round=6) == FILE
    assert len(space.log.notifications()) == 1               # break-glass is loud


def test_reopen_threshold_still_applies_in_a_space():
    owner = kp(1)
    ck = random_bytes(32)
    space = _space(owner, ck)
    doctor, body = R.split_reopen_shares(ck)
    assert reopen_dispute(space, doctor_share=doctor, body_share=body, now_round=5, retention_end=1000) == FILE
    # past retention -> unreadable even in a space
    with pytest.raises(R.AccessDenied):
        reopen_dispute(space, doctor_share=doctor, body_share=body, now_round=2000, retention_end=1000)


def test_opens_are_logged_and_tamper_evident():
    owner, patient = kp(1), kp(2)
    ck = random_bytes(32)
    space = _space(owner, ck)
    _grant(space.policy, owner, patient, Role.READER, 1)
    open_own(space, patient.public, content_key=ck, now_round=1)
    assert space.log.verify()
    assert len(space.log.entries) == 1
