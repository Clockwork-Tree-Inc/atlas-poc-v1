"""Independent per-device continuity-ratchet cadence (§5.3, §16, §18).

Corrected model: clock jitter is BIOLOGICAL (from the enrolled ring signal, never
an RNG); the beacon is consumed FRESH each tick (no cache); a stale/absent beacon
is fail-closed (inert), never folded; and no timing is folded into the key value.
"""

import os

import pytest

from atlas.liveness.bayes import LivenessGate
from atlas.liveness.synthetic import live_stream, spoof_stream
from atlas.keys.identity import build_identity_tree
from atlas.session.cadence import RatchetClock
from atlas.session.device import Device, EpochInputs

BEACON = b"beacon-fresh" * 3   # a stand-in current beacon consumed at a tick


def _pole(stream, epoch=b"\x00" * 8):
    g = LivenessGate()
    for _, (psl, psnl) in stream:
        g.update(p_s_given_live=psl, p_s_given_not_live=psnl)
    return g.state(sensor_digest=b"s", drand_round=epoch)


def _device(name="A", clock=None):
    d = Device(name, build_identity_tree(os.urandom(32)),
               bootstrap_tunnel_key=os.urandom(32), ratchet_clock=clock)
    d.advance_epoch_present(lk=b"L" * 32, epoch_key=b"E" * 32, drand_round=b"\x00" * 8)
    return d


# -- #16: the clock is timed by the BIOLOGICAL signal, not an RNG ------------

def test_biological_jitter_spans_the_band_and_is_not_an_rng():
    clk = RatchetClock(nominal_s=10.0, jitter_s=2.0)
    # a sample byte from the live ring signal maps deterministically to a WHEN
    xs = [clk.next_interval(bio_signal=bytes([b])) for b in range(256)]
    assert all(8.0 <= x <= 12.0 for x in xs)          # within [nominal ± jitter]
    assert min(xs) < 9.0 and max(xs) > 11.0           # the biological signal spans it
    # deterministic in the biological sample (a schedule fn, not an RNG draw):
    assert clk.next_interval(bio_signal=b"\x80") == clk.next_interval(bio_signal=b"\x80")
    # no bio signal -> cannot time the clock (no silent RNG fallback)
    with pytest.raises(ValueError):
        clk.next_interval(bio_signal=b"")


def test_jitter_must_be_smaller_than_nominal():
    with pytest.raises(ValueError):
        RatchetClock(nominal_s=10.0, jitter_s=10.0)
    with pytest.raises(ValueError):
        RatchetClock(nominal_s=10.0, jitter_s=-1.0)


def test_two_devices_desync_from_different_biological_streams():
    a, b = RatchetClock(), RatchetClock()
    # different live streams -> different schedules (independent cadence, from
    # biology not an RNG)
    seq_a = [a.next_interval(bio_signal=bytes([i % 256])) for i in range(50)]
    seq_b = [b.next_interval(bio_signal=bytes([(i * 7 + 3) % 256])) for i in range(50)]
    assert seq_a != seq_b


# -- the device continuity tick (fresh beacon, no timing in value) -----------

def test_operate_tick_advances_key_and_emits_fresh_attestation():
    d = _device()
    t1 = d.continuity_tick(_pole(live_stream(40)), drand_round=b"\x00" * 8, beacon=BEACON, challenge=b"chal-1")
    assert t1.operate and t1.attestation is not None
    assert t1.attestation.verify() and t1.attestation.challenge == b"chal-1"
    t2 = d.continuity_tick(_pole(live_stream(40)), drand_round=b"\x00" * 8, beacon=BEACON, challenge=b"chal-2")
    assert t2.continuity_key not in (b"", t1.continuity_key)   # one-way ratchet advances


def test_realised_interval_does_not_enter_the_key(monkeypatch):
    """#16 must not become timing-in-a-value (#23): the biological schedule
    (interval) is NOT folded into the ratchet key. With the QRNG entropy pinned,
    two devices whose clocks realise DIFFERENT intervals produce the SAME key —
    the interval is a WHEN, not an ingredient."""
    monkeypatch.setattr("atlas.session.device.random_bytes", lambda n: b"\x07" * n)
    monkeypatch.setattr("atlas.session.pole.random_bytes", lambda n: b"\x07" * n)
    seed = os.urandom(32); boot = os.urandom(32)

    def key_for(bio_byte):
        d = Device("A", build_identity_tree(seed), bootstrap_tunnel_key=boot,
                   ratchet_clock=RatchetClock(nominal_s=10.0, jitter_s=2.0))
        d.advance_epoch_present(lk=b"L" * 32, epoch_key=b"E" * 32, drand_round=b"\x00" * 8)
        d.next_ratchet_interval(bio_signal=bytes([bio_byte]))   # realises an interval
        return d.continuity_tick(_pole(live_stream(40)), drand_round=b"\x00" * 8, beacon=BEACON).continuity_key

    assert key_for(0x10) != 0                          # sanity: a key was produced
    assert key_for(0x10) == key_for(0xF0)              # different interval -> SAME key


def test_beacon_consumed_fresh_and_changes_the_key(monkeypatch):
    monkeypatch.setattr("atlas.session.device.random_bytes", lambda n: b"\x07" * n)
    monkeypatch.setattr("atlas.session.pole.random_bytes", lambda n: b"\x07" * n)
    seed = os.urandom(32); boot = os.urandom(32)

    def key_with(beacon):
        d = Device("A", build_identity_tree(seed), bootstrap_tunnel_key=boot,
                   ratchet_clock=RatchetClock(nominal_s=10.0, jitter_s=0.0))
        d.advance_epoch_present(lk=b"L" * 32, epoch_key=b"E" * 32, drand_round=b"\x00" * 8)
        return d.continuity_tick(_pole(live_stream(40)), drand_round=b"\x00" * 8, beacon=beacon).continuity_key

    assert key_with(b"beacon-A" * 4) != key_with(b"beacon-B" * 4)   # fresh beacon folds in


def test_stale_or_absent_beacon_is_fail_closed_not_fail_stale():
    """#18: no cache. A missing/stale beacon at tick time makes the device INERT
    (fail-closed) — it wipes and does not ratchet; it NEVER folds a prior value."""
    d = _device()
    _ = d.session.key                                  # a live key exists
    tick = d.continuity_tick(_pole(live_stream(40)), drand_round=b"\x00" * 8, beacon=b"")
    assert not tick.operate and tick.continuity_key == b""
    assert d._continuity_key is None                   # inert: no key material at rest
    with pytest.raises(Exception):
        _ = d.session.key                              # session wiped (fail-closed)


def test_liveness_break_tick_wipes_and_advances_no_key():
    d = _device()
    wiped = {"v": False}
    d.attestation.on_wipe(lambda: (d._wipe_session(), wiped.__setitem__("v", True)))
    _ = d.session.key
    tick = d.continuity_tick(_pole(spoof_stream(40)), drand_round=b"\x00" * 8, beacon=BEACON)
    assert not tick.operate and tick.attestation is None and tick.continuity_key == b""
    assert wiped["v"]
    assert d._continuity_key is None
    with pytest.raises(Exception):
        _ = d.session.key
