"""R10 ring wired as the coherent-biology liveness anchor.

The ring drops into the SAME SignalSource pipeline as ambient (source swap, no
rewiring); it is NOT simulated (real biology); a removed/spoofed ring fails closed;
and its HRV populates the GBSS h_i channel the phone cannot produce. Biological
signal times/gates — never a key/value.
"""

import os

import pytest

from atlas.keys.identity import build_identity_tree
from atlas.liveness.bayes import LivenessGate
from atlas.liveness.gbss import (
    entropy_vector_with_ring,
    fuse_motion_s_i,
    pole_from_gbss,
    ring_h_i,
    ring_s_i,
)
from atlas.liveness.synthetic import live_stream, spoof_stream
from atlas.session import pole as pole_mod
from atlas.session.device import Device
from atlas.session.signal_source import (
    RingSignalSource,
    SignalSourceUnavailable,
    timed_ratchet_step,
)

BEACON = b"beacon-fresh" * 3


def _live_window(n=16):
    return [s for s, _ in live_stream(n)]


def _spoof_window(n=16):
    return [s for s, _ in spoof_stream(n)]


def _live_sampler(n=40):
    it = iter(_live_window(n))
    return lambda: next(it, None)


def _pole():
    g = LivenessGate()
    for _, (psl, psnl) in live_stream(40):
        g.update(p_s_given_live=psl, p_s_given_not_live=psnl)
    return g.state(sensor_digest=b"s", drand_round=b"\x00" * 8)


def _device():
    d = Device("A", build_identity_tree(os.urandom(32)), bootstrap_tunnel_key=os.urandom(32))
    d.advance_epoch_present(lk=b"L" * 32, epoch_key=b"E" * 32, drand_round=b"\x00" * 8)
    return d


# -- the ring as a wired SignalSource ----------------------------------------

def test_no_sampler_still_deferred_refuses_to_fake_biology():
    with pytest.raises(SignalSourceUnavailable):
        RingSignalSource().sample()


def test_live_pulse_is_present_and_NOT_simulated():
    s = RingSignalSource(sampler=_live_sampler()).sample()
    assert s.present is True
    assert s.simulated is False          # the honesty flip: real biology, not the ambient stand-in
    assert s.kind == "ring"


def test_removed_or_spoofed_ring_fails_closed():
    assert RingSignalSource(sampler=lambda: None).sample().present is False   # removed
    it = iter(_spoof_window(20))
    assert RingSignalSource(sampler=lambda: next(it, None)).sample().present is False  # flat HRV spoof


def test_imu_catches_motionless_ring_even_with_a_plausible_pulse():
    """The ring's IMU is the on-body / anti-removal gate: a ring reporting a perfect
    pulse but ZERO motion (removed / on a table / a replayed pulse on a still ring)
    is not on a body -> fail-closed, even though HR + HRV look live."""
    from atlas.liveness.synthetic import SensorSample
    still = SensorSample(hr=68.0, hrv_ms=45.0, spo2=98.0, accel_mag=0.001)  # good pulse, no motion
    assert RingSignalSource(sampler=lambda: still).sample().present is False
    worn = SensorSample(hr=68.0, hrv_ms=45.0, spo2=98.0, accel_mag=0.02)    # same pulse, on-body motion
    assert RingSignalSource(sampler=lambda: worn).sample().present is True


def test_ring_swaps_into_the_pipeline_unchanged():
    """Source-agnostic: the ring drives timed_ratchet_step exactly like ambient."""
    r = timed_ratchet_step(_device(), RingSignalSource(sampler=_live_sampler()),
                           pole=_pole(), drand_round=b"\x00" * 8, beacon=BEACON)
    assert not r.gated_out and r.tick is not None and r.source_kind == "ring" and r.simulated is False


def test_removed_ring_gates_the_ratchet_closed():
    r = timed_ratchet_step(_device(), RingSignalSource(sampler=lambda: None),
                           pole=_pole(), drand_round=b"\x00" * 8, beacon=BEACON)
    assert r.gated_out and r.tick is None   # liveness break -> no advance


def test_ring_timing_never_enters_the_value(monkeypatch):
    """Two different biological samples give different TIMING but the SAME QRNG value."""
    monkeypatch.setattr(pole_mod, "random_bytes", lambda n: b"Q" * n)
    from atlas.liveness.synthetic import SensorSample
    a = SensorSample(hr=60.0, hrv_ms=45.0, spo2=98.0, accel_mag=0.02)
    b = SensorSample(hr=90.0, hrv_ms=20.0, spo2=98.0, accel_mag=0.02)
    s1 = RingSignalSource(sampler=lambda: a).sample()
    s2 = RingSignalSource(sampler=lambda: b).sample()
    assert s1.timing != s2.timing               # biology carries a real WHEN
    v1 = pole_mod.fire_pole_value(physio_fire_moment=s1.timing[0] / 255.0)
    v2 = pole_mod.fire_pole_value(physio_fire_moment=s2.timing[0] / 255.0)
    assert v1 == v2 == b"Q" * 32                # ...but never the value


# -- the ring populates GBSS h_i (the involuntary core) ----------------------

def test_ring_h_i_high_for_live_low_for_spoof():
    assert ring_h_i(_live_window()) > 0.5       # complex living HRV -> high
    assert ring_h_i(_spoof_window()) < 0.3      # flat/metronomic HRV -> low
    assert ring_h_i(_live_window(3)) == 0.0     # too short -> 0


def test_vector_gains_h_i_when_ring_present_else_ring_deferred():
    with_ring = entropy_vector_with_ring(s_i=0.7, c_i=0.6, m_i=0.5, ring_window=_live_window())
    assert with_ring.ring_deferred() is False
    assert set(with_ring.present().keys()) == {"h_i", "s_i", "m_i", "c_i"}   # all FOUR channels
    without = entropy_vector_with_ring(s_i=0.7, c_i=0.6, ring_window=None)
    assert without.ring_deferred() is True and "h_i" not in without.present()


def test_ring_imu_feeds_s_i_high_for_live_wrist_low_for_still():
    assert ring_s_i(_live_window()) > 0.5        # complex on-wrist micro-movement -> high
    assert ring_s_i(_spoof_window()) < 0.35      # near-zero flat motion (still/removed) -> low
    assert ring_s_i(_live_window(3)) == 0.0       # too short


def test_s_i_is_fused_with_the_ring_when_present():
    # with a live ring, s_i is fused (on-body ring weighted higher) -> differs from phone-only
    fused = fuse_motion_s_i(0.3, _live_window())
    assert fused > 0.3 and fused != 0.3
    # no ring -> s_i is the phone's alone (unchanged)
    assert fuse_motion_s_i(0.3, None) == 0.3
    # the vector's s_i reflects the fusion when the ring is present
    v = entropy_vector_with_ring(s_i=0.3, c_i=0.6, m_i=0.5, ring_window=_live_window())
    assert v.s_i != 0.3 and v.s_i > 0.3


def test_live_ring_liveness_operates():
    vecs = [entropy_vector_with_ring(s_i=0.85, c_i=0.8, m_i=0.75, ring_window=_live_window())
            for _ in range(45)]
    assert pole_from_gbss(vecs, drand_round=b"\x00" * 8).operate is True
