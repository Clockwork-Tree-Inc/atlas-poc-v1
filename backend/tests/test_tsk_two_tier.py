"""Two-tier TSK recovery: Shamir(your-half) ∧ Shamir(server-half), both mandatory.

The load-bearing property: the server/institutional side can NEVER reconstruct the seed —
even with ALL its shares — because it only holds server_half, which is independent of the
seed. Reconstruction requires a threshold of YOUR holders too.
"""

import pytest

from atlas.keys.tsk_two_tier import (
    HolderClassError,
    ThresholdNotMet,
    reconstruct_tsk_two_tier,
    split_tsk_two_tier,
    default_holders,
)
from atlas.recovery.threshold_seal import Custodian, ThresholdPolicy

SEED = bytes(range(32)) + bytes(range(32))          # 64 bytes, deterministic
UPOL = ThresholdPolicy(n=3, m=2)                    # your half: 2-of-3
SPOL = ThresholdPolicy(n=3, m=2)                    # server half: 2-of-3


def _split():
    u, s = default_holders()
    return split_tsk_two_tier(SEED, user_holders=u, server_holders=s,
                              user_policy=UPOL, server_policy=SPOL)


def test_roundtrip_needs_both_halves():
    sh = _split()
    got = reconstruct_tsk_two_tier(
        user_shares=sh.user_shares[:2], server_shares=sh.server_shares[:2],
        user_policy=UPOL, server_policy=SPOL)
    assert got == SEED


def test_server_side_alone_can_never_reconstruct():
    # ALL server shares, zero user shares -> fail-closed. This is the whole point.
    sh = _split()
    with pytest.raises(ThresholdNotMet):
        reconstruct_tsk_two_tier(
            user_shares=[], server_shares=sh.server_shares,
            user_policy=UPOL, server_policy=SPOL)


def test_your_side_alone_can_never_reconstruct():
    sh = _split()
    with pytest.raises(ThresholdNotMet):
        reconstruct_tsk_two_tier(
            user_shares=sh.user_shares, server_shares=[],
            user_policy=UPOL, server_policy=SPOL)


def test_below_threshold_on_your_side_fails():
    sh = _split()
    with pytest.raises(ThresholdNotMet):
        reconstruct_tsk_two_tier(
            user_shares=sh.user_shares[:1], server_shares=sh.server_shares[:2],
            user_policy=UPOL, server_policy=SPOL)


def test_fault_tolerant_lose_one_each_side():
    # lose one of your holders and one server node -> the remaining 2+2 still recover.
    sh = _split()
    got = reconstruct_tsk_two_tier(
        user_shares=[sh.user_shares[0], sh.user_shares[2]],
        server_shares=[sh.server_shares[1], sh.server_shares[2]],
        user_policy=UPOL, server_policy=SPOL)
    assert got == SEED


def test_server_half_is_independent_of_seed():
    # server_half (reconstructed from server shares) must NOT equal the seed or leak it.
    from atlas.crypto import shamir
    sh = _split()
    server_half = shamir.combine([s.share for s in sh.server_shares[:2]])
    assert server_half != SEED
    assert len(server_half) == len(SEED)


def test_rejects_institutional_user_holder():
    u = [Custodian(label="phone", institutional=True),
         Custodian(label="usb", institutional=False),
         Custodian(label="contact", institutional=False)]
    _, s = default_holders()
    with pytest.raises(HolderClassError):
        split_tsk_two_tier(SEED, user_holders=u, server_holders=s,
                           user_policy=UPOL, server_policy=SPOL)


def test_rejects_noninstitutional_server_holder():
    u, _ = default_holders()
    s = [Custodian(label="node-a", institutional=True),
         Custodian(label="node-b", institutional=False),
         Custodian(label="node-c", institutional=True)]
    with pytest.raises(HolderClassError):
        split_tsk_two_tier(SEED, user_holders=u, server_holders=s,
                           user_policy=UPOL, server_policy=SPOL)
