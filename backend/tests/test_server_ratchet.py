"""Tests for the server-share proactive ratchet with Feldman VSS (TRUST_LAYER.md Group E)."""

import pytest

from atlas.crypto.primitives import random_bytes
from atlas.keys.identity import reassemble_system_id
from atlas.keys.server_ratchet import CheatingShard, JurisdictionShard, RatchetError, ServerShareRatchet

JURIS = ["eu", "us", "asia", "latam", "africa"]


def _ratchet(k=3, n=5, secret=None):
    secret = secret or random_bytes(32)
    return ServerShareRatchet(secret, JURIS[:n], k=k), secret


def test_refresh_preserves_the_server_share():
    r, secret = _ratchet(k=3, n=5)
    assert r.reconstruct(r.shards[:3]) == secret
    r.proactive_refresh(epoch_trigger=(1).to_bytes(8, "big"))
    assert r.reconstruct(r.shards[:3]) == secret          # value unchanged
    assert r.epoch == 1


def test_refresh_rotates_the_shares():
    r, _ = _ratchet()
    before = [sh.share for sh in r.shards]
    r.proactive_refresh(epoch_trigger=(1).to_bytes(8, "big"))
    after = [sh.share for sh in r.shards]
    assert all(b != a for b, a in zip(before, after))     # every share moved


def test_secret_commitment_is_invariant_across_refresh():
    # G^secret must not move — cryptographic proof the System-ID is untouched.
    r, _ = _ratchet()
    c0 = r.secret_commitment
    for e in range(1, 4):
        r.proactive_refresh(epoch_trigger=e.to_bytes(8, "big"))
        assert r.secret_commitment == c0


def test_system_id_is_stable_across_refresh():
    user_half = random_bytes(32)
    r, _ = _ratchet()
    sid_before = reassemble_system_id(user_half, r.reconstruct(r.shards[:3]))
    for e in range(1, 4):
        r.proactive_refresh(epoch_trigger=e.to_bytes(8, "big"))
        assert reassemble_system_id(user_half, r.reconstruct(r.shards[:3])) == sid_before


# --------------------------------------------------------------------------- VSS: cheater detection
def test_cheating_shard_is_detected():
    r, _ = _ratchet(k=3, n=5)
    present = list(r.shards[:3])
    present[1] = JurisdictionShard(present[1].jurisdiction, present[1].index,
                                   present[1].share + 1)          # corrupt one share
    with pytest.raises(CheatingShard):
        r.reconstruct(present)


def test_shares_are_feldman_verifiable():
    r, _ = _ratchet()
    for sh in r.shards:
        assert r.verify_share(sh.index, sh.share)                 # honest shares verify
        assert not r.verify_share(sh.index, sh.share + 1)         # a tweaked share does not


def test_roving_adversary_cannot_mix_epochs():
    # shares captured across DIFFERENT epochs now FAIL verification against the current
    # commitments -> detected as cheating, not silently combined.
    r, secret = _ratchet(k=3, n=5)
    epoch0 = list(r.shards)
    r.proactive_refresh(epoch_trigger=(1).to_bytes(8, "big"))
    epoch1 = list(r.shards)
    assert r.reconstruct(epoch1[:3]) == secret                    # a single-epoch quorum works
    with pytest.raises(CheatingShard):
        r.reconstruct([epoch0[0], epoch0[1], epoch1[2]])          # mixed epochs -> detected


def test_value_is_fresh_qrng_not_from_the_trigger():
    secret = random_bytes(32)
    r1 = ServerShareRatchet(secret, JURIS, k=3)
    r2 = ServerShareRatchet(secret, JURIS, k=3)
    trig = (7).to_bytes(8, "big")
    r1.proactive_refresh(epoch_trigger=trig)
    r2.proactive_refresh(epoch_trigger=trig)
    assert r1.shards[0].share != r2.shards[0].share               # not derived from the trigger
    assert r1.reconstruct(r1.shards[:3]) == r2.reconstruct(r2.shards[:3]) == secret


# --------------------------------------------------------------------------- fail-closed
def test_below_quorum_fails_closed():
    r, _ = _ratchet(k=3, n=5)
    with pytest.raises(RatchetError):
        r.reconstruct(r.shards[:2])


def test_refresh_requires_a_trigger():
    r, _ = _ratchet()
    with pytest.raises(RatchetError):
        r.proactive_refresh(epoch_trigger=b"")


def test_policy_validation():
    with pytest.raises(RatchetError):
        ServerShareRatchet(random_bytes(32), ["eu"], k=1)          # k must be > 1
    with pytest.raises(RatchetError):
        ServerShareRatchet(random_bytes(32), ["eu", "us"], k=3)    # k <= n
