"""The public EPOCH KEY is the LKG aggregator's QRNG epoch beacon — NOT external drand.

Asserts the model the codebase now enforces:
  * the epoch value is CLEAN QRNG — neither the LK-arrival timing nor the external-drand
    `anchor` enters it (hold the core constant, vary timing+anchor -> identical value);
  * the epoch index advances monotonically (random cadence, driven by arrivals);
  * an aggregator-signed round verifies, and any tamper or a missing signature fails closed;
  * the drand `anchor` is recorded and bound into the signature for defence-in-depth, never
    into the value.
"""
import os

import pytest

from atlas.beacon import ArrivalTiming, EpochBeacon, verify_epoch_round
from atlas.beacon.epoch import EpochRound
from atlas.crypto.sign import generate_sig_keypair


def _arr(*ts):
    return ArrivalTiming(timestamps=list(ts))


def test_value_is_clean_qrng_independent_of_timing_and_anchor():
    core = os.urandom(32)
    fast = EpochBeacon().fire(_arr(0.0, 0.1, 0.2), anchor=b"\x07" * 8, entropy_core=core)
    slow = EpochBeacon().fire(_arr(0.0, 0.9, 2.0), anchor=b"\xff" * 8, entropy_core=core)
    # same core, different arrival timing AND different drand anchor -> identical value
    assert fast.randomness == slow.randomness
    # a fresh core changes the value
    assert EpochBeacon().fire(_arr(0.0, 0.1), entropy_core=os.urandom(32)).randomness != fast.randomness


def test_epoch_index_is_monotonic_and_8_bytes():
    b = EpochBeacon()
    r1 = b.fire(_arr(0.0, 0.1))
    r2 = b.fire(_arr(0.0, 0.2))
    assert (r1.epoch, r2.epoch) == (1, 2)
    assert r2.epoch_round() == (2).to_bytes(8, "big")
    assert b.latest().epoch == 2


def test_signed_round_verifies_and_tamper_fails_closed():
    agg = generate_sig_keypair()
    b = EpochBeacon(signer=agg)
    r = b.fire(_arr(0.0, 0.1, 0.2), anchor=b"\x07" * 8)
    assert verify_epoch_round(r, agg.public)
    # tamper the value, the epoch, or the anchor -> verification fails
    assert not verify_epoch_round(EpochRound(r.epoch, b"x" * 32, r.anchor, r.signature), agg.public)
    assert not verify_epoch_round(EpochRound(r.epoch + 1, r.randomness, r.anchor, r.signature), agg.public)
    assert not verify_epoch_round(EpochRound(r.epoch, r.randomness, b"\x00" * 8, r.signature), agg.public)
    # a different aggregator key does not verify
    assert not verify_epoch_round(r, generate_sig_keypair().public)


def test_unsigned_poc_round_does_not_verify():
    r = EpochBeacon().fire(_arr(0.0, 0.1))          # no signer -> empty signature
    assert r.signature == b""
    assert not verify_epoch_round(r, generate_sig_keypair().public)


def test_latest_before_fire_raises():
    with pytest.raises(RuntimeError):
        EpochBeacon().latest()
