"""Beacon + QRNG loop (§3)."""

import os

from atlas.beacon import ArrivalTiming, LocalBeacon, ServerQRNG
from atlas.beacon.drand import DrandHTTPBeacon


def test_local_beacon_advances_and_is_stable_within_epoch():
    b = LocalBeacon(genesis_time=0.0, period_s=3.0)
    r1a = b.round_at(3.2)
    r1b = b.round_at(4.9)
    r2 = b.round_at(6.1)
    assert r1a.round == r1b.round == 2
    assert r1a.randomness == r1b.randomness            # stable within epoch
    assert r2.round == 3 and r2.randomness != r1a.randomness  # advances


def test_local_beacon_is_deterministic():
    a = LocalBeacon(period_s=3.0)
    b = LocalBeacon(period_s=3.0)
    assert a.round_at(10.0).randomness == b.round_at(10.0).randomness


def test_qrng_value_is_clean_timing_only_schedules():
    q = ServerQRNG(base_period_s=3.0)
    arr = ArrivalTiming(timestamps=[100.0, 100.21, 100.55])
    arr2 = ArrivalTiming(timestamps=[100.0, 100.9, 101.0])
    core = os.urandom(32)
    # timing does NOT enter the value: same core + different timing -> SAME value
    assert q.fire(arr, b"\x00" * 8, entropy_core=core).randomness == \
           q.fire(arr2, b"\x00" * 8, entropy_core=core).randomness
    # value is clean QRNG: fresh core each fire -> different value
    assert q.fire(arr, b"\x00" * 8).randomness != q.fire(arr, b"\x00" * 8).randomness
    # timing is retained only as a schedule/audit commitment (NOT in the value)
    assert q.fire(arr, b"\x00" * 8).timing_commitment == arr.digest()


def test_qrng_times_next_sampling():
    q = ServerQRNG(base_period_s=3.0)
    d = q.fire(ArrivalTiming(timestamps=[0.0, 0.5, 1.0]), b"\x00" * 8)
    assert 3.0 <= d.next_sampling_offset_s <= 6.0       # presence-derived jitter


def test_drand_client_against_stub_transport():
    import hashlib
    sig = bytes([0xbb]) * 48
    rnd = hashlib.sha256(sig).hexdigest()   # randomness == H(signature) binding

    def stub(url):
        if url.endswith("/info"):
            return {"period": 3, "genesis_time": 1692803367}
        return {"round": 42, "randomness": rnd, "signature": sig.hex()}

    # transport + hash-binding test only (fake signature) — BLS authenticity is covered
    # against a real round in test_drand_bls.py, so opt out of BLS here.
    dr = DrandHTTPBeacon(http_get=stub, verify_bls=False)
    dr.info()
    r = dr.latest()
    assert r.round == 42 and len(r.randomness) == 32


def test_drand_client_rejects_tampered_randomness():
    """Security review fix: a relay returning randomness != H(signature) is rejected."""
    def stub(url):
        if url.endswith("/info"):
            return {"period": 3, "genesis_time": 0}
        return {"round": 7, "randomness": "aa" * 32, "signature": "bb" * 48}  # mismatch
    import pytest
    with pytest.raises(ValueError):
        DrandHTTPBeacon(http_get=stub).latest()
