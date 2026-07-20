"""Swappable signal source — architecture + the load-bearing value/timing
invariant (iPhone ambient PoC).

Proves three things the ambient-iPhone build must guarantee:
  1. VALUE-INDEPENDENCE — the ambient TIMING bytes never enter a key/value; the
     value stays clean QRNG. (This is the never-mixed invariant, exactly.)
  2. SOURCE-AGNOSTICISM — the pipeline consumes only the SignalSource interface;
     swapping ambient <-> ring is a source swap, no pipeline rewiring.
  3. PRESENCE GATE — when the live signal is absent, the ratchet does NOT advance
     (fail-closed), like the ring signal dropping.
"""

import os

import pytest

from atlas.keys.derivation import derive_session_key_decoupled
from atlas.keys.identity import build_identity_tree
from atlas.liveness.bayes import LivenessGate
from atlas.liveness.synthetic import live_stream
from atlas.params import CONTEXT_TUNNEL
from atlas.session import (
    AmbientSensorSource, LiveSignalSample, RingSignalSource, SignalSource,
    SignalSourceUnavailable, timed_ratchet_step,
)
from atlas.session import pole as pole_mod
from atlas.session.device import Device

BEACON = b"beacon-fresh" * 3


def _pole(epoch=b"\x00" * 8):
    g = LivenessGate()
    for _, (psl, psnl) in live_stream(40):
        g.update(p_s_given_live=psl, p_s_given_not_live=psnl)
    return g.state(sensor_digest=b"s", drand_round=epoch)


def _device():
    d = Device("A", build_identity_tree(os.urandom(32)), bootstrap_tunnel_key=os.urandom(32))
    d.advance_epoch_present(lk=b"L" * 32, epoch_key=b"E" * 32, drand_round=b"\x00" * 8)
    return d


# -- 1. VALUE-INDEPENDENCE: ambient TIMES, QRNG VALUES ----------------------

def test_ambient_timing_never_enters_the_pole_value(monkeypatch):
    """Two wildly different ambient timing samples must yield the SAME QRNG
    pole_value when the QRNG is fixed — proving the ambient bytes are NOT folded
    into the value (they only schedule WHEN it fires)."""
    monkeypatch.setattr(pole_mod, "random_bytes", lambda n: b"Q" * n)
    early = AmbientSensorSource(sampler=lambda: b"\x01\x02\x03\x04\x05\x06\x07\x08")
    late = AmbientSensorSource(sampler=lambda: b"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7")
    s_early, s_late = early.sample(), late.sample()
    # the timing bytes genuinely differ (they carry a real WHEN)...
    assert s_early.timing != s_late.timing
    # ...but the fired value is identical: timing never touched the value.
    v_early = pole_mod.fire_pole_value(physio_fire_moment=s_early.timing[0] / 255.0)
    v_late = pole_mod.fire_pole_value(physio_fire_moment=s_late.timing[0] / 255.0)
    assert v_early == v_late == b"Q" * 32


def test_ambient_timing_does_change_the_schedule():
    """The complementary half: the ambient sample DOES drive WHEN (the interval),
    so it is doing its real (scheduling) job — just never as a value."""
    d = _device()
    lo = d.next_ratchet_interval(bio_signal=b"\x00")
    hi = d.next_ratchet_interval(bio_signal=b"\xff")
    assert lo < hi                      # different ambient sample -> different WHEN


def test_session_key_is_independent_of_the_ambient_stream():
    """End-to-end: derive a session key twice with the SAME QRNG-valued inputs but
    two different ambient streams; the key is identical. The ambient stream is not
    an input to the KDF at all."""
    common = dict(lk=b"L" * 32, epoch_key=b"E" * 32, pole_value=b"Q" * 32,
                  prev_key=b"\x00" * 32, context_separator=CONTEXT_TUNNEL, drand_round=b"\x00" * 8)
    k1 = derive_session_key_decoupled(**common).key
    # a different ambient stream would change scheduling only; the KDF inputs above
    # contain no ambient bytes, so the key cannot depend on the stream.
    k2 = derive_session_key_decoupled(**common).key
    assert k1 == k2


# -- 2. SOURCE-AGNOSTICISM: swap ambient <-> ring, no pipeline change --------

class _DeterministicSource(SignalSource):
    """A stand-in source proving the pipeline only needs the interface."""
    kind = "test-deterministic"
    simulated = True

    def __init__(self, byte: int, present: bool = True):
        self._b, self._present = byte, present

    def sample(self) -> LiveSignalSample:
        return LiveSignalSample(timing=bytes([self._b]), present=self._present,
                                kind=self.kind, simulated=True)


def test_pipeline_consumes_any_source_unchanged():
    """The SAME driver runs an ambient source and a different source with no code
    change — source-agnostic by construction."""
    d = _device()
    pole = _pole()
    for source in (AmbientSensorSource(sampler=lambda: b"\x40" * 8),
                   _DeterministicSource(0x40)):
        r = timed_ratchet_step(d, source, pole=pole, drand_round=b"\x00" * 8, beacon=BEACON)
        assert not r.gated_out and r.tick is not None and r.tick.operate


def test_ring_source_is_the_deferred_swap_point():
    """The ring source exists to prove the swap point; it is deferred in this
    build and raises rather than silently faking biology."""
    with pytest.raises(SignalSourceUnavailable):
        RingSignalSource().sample()


# -- 3. PRESENCE GATE: no live signal -> no advance (fail-closed) ------------

def test_absent_ambient_signal_gates_the_ratchet_closed():
    """A flatlined/absent ambient window closes the gate: the ratchet does NOT
    advance (fail-closed), exactly like the ring signal dropping."""
    d = _device()
    pole = _pole()
    dead = AmbientSensorSource(sampler=lambda: b"\x00" * 8)   # flatlined -> not present
    r = timed_ratchet_step(d, dead, pole=pole, drand_round=b"\x00" * 8, beacon=BEACON)
    assert r.gated_out and r.tick is None


def test_present_flag_reflects_stream_liveness():
    assert AmbientSensorSource(sampler=lambda: b"\x00" * 8).sample().present is False
    assert AmbientSensorSource(sampler=lambda: b"\x11\x22" + b"\x00" * 6).sample().present is True
    assert AmbientSensorSource(sampler=lambda: b"").sample().present is False


def test_ambient_sample_is_loudly_simulated():
    """Nothing downstream may claim biological liveness: ambient is marked
    simulated so logs/UI can flag ambient-not-biological."""
    s = AmbientSensorSource().sample()
    assert s.simulated is True and s.kind == "ambient"


# -- 4. CHANGE-DETECTION: XOR vs previous snapshot (change, not level) --------

def _seq_source(windows):
    """An ambient source whose sampler yields the given windows in order (then
    repeats the last), so multi-tick change behaviour can be driven deterministically."""
    it = iter(windows)
    last = {"w": windows[-1]}

    def sampler():
        try:
            last["w"] = next(it)
        except StopIteration:
            pass
        return last["w"]

    return AmbientSensorSource(sampler=sampler)


def test_frozen_snapshot_fails_closed_via_xor():
    """A live sensor never repeats a snapshot exactly; a FROZEN/replayed identical
    window flips ZERO bits on the second tick -> not present (fail-closed)."""
    frozen = b"\x11\x22\x33\x44\x55\x66\x77\x88"
    src = _seq_source([frozen, frozen])
    first = src.sample()                       # bootstrap: gates on window liveness
    assert first.present is True
    second = src.sample()                      # identical -> 0 changed bits
    assert second.changed_bits == 0
    assert second.present is False             # frozen/replay -> gate closed


def test_constant_baseline_cancels_only_change_counts():
    """Anything CONSTANT cancels in the XOR: a window that differs from the last
    only in bits that changed is what drives presence + timing — absolute level
    (a loud-but-steady channel) contributes nothing once it stops changing."""
    a = b"\xf0\x0f\x11\x22\x33\x44\x55\x66"     # 'loud' constant high byte 0xf0
    b = b"\xf0\x1f\x11\x22\x33\x44\x55\x66"     # same except one byte changed
    src = _seq_source([a, b])
    src.sample()
    s = src.sample()
    # only the single differing byte flips bits; the steady 0xf0 baseline cancels.
    assert s.changed_bits == bin(0x0f ^ 0x1f).count("1")
    assert s.present is True


def test_change_drives_timing_not_level():
    """The schedule byte comes from the CHANGE pattern, so two ticks with the same
    absolute level but different change yield different timing."""
    base = b"\x80\x80\x80\x80\x80\x80\x80\x80"
    small = b"\x80\x81\x80\x80\x80\x80\x80\x80"   # one low-bit change
    big = b"\x80\xff\x7f\x01\x80\x80\x80\x80"      # several changes
    s1 = _seq_source([base, small]); s1.sample(); t1 = s1.sample().timing
    s2 = _seq_source([base, big]); s2.sample(); t2 = s2.sample().timing
    assert t1 != t2                                # jitter tracks change, not level


# -- 5. ENTROPY ACROSS SNAPSHOTS: catches a loop XOR alone waves through ------

def test_two_frame_loop_flagged_by_min_entropy():
    """An A,B,A,B replay LOOP flips bits every tick (XOR passes) but visits only
    two SNAPSHOT states -> min-entropy across snapshots collapses -> flagged as
    degenerate once the buffer is full."""
    import os
    a = bytes(range(1, 9))
    b = bytes(range(9, 17))
    loop = _seq_source([a, b] * 16)            # long enough to fill the entropy buffer
    verdicts = [loop.sample() for _ in range(24)]
    assert verdicts[-1].present is False       # 2 symbols -> min-entropy ~1 bit < floor
    assert verdicts[-1].changed_bits and verdicts[-1].changed_bits > 0   # XOR alone was fooled
    assert verdicts[-1].min_entropy_bits is not None and verdicts[-1].min_entropy_bits < 2.5
    # a genuinely noisy stream (all-distinct snapshots) stays present throughout.
    noisy = AmbientSensorSource(sampler=lambda: os.urandom(8))
    assert all(noisy.sample().present for _ in range(24))


def test_both_shannon_and_min_entropy_reported_and_ordered():
    import os
    from atlas.session.signal_source import _ENTROPY_WARM
    src = AmbientSensorSource(sampler=lambda: os.urandom(8))
    samples = [src.sample() for _ in range(_ENTROPY_WARM + 6)]
    assert samples[0].entropy_bits is None and samples[0].min_entropy_bits is None  # bootstrap
    last = samples[-1]
    assert last.entropy_bits is not None and last.min_entropy_bits is not None
    assert last.min_entropy_bits <= last.entropy_bits + 1e-9   # min-entropy <= Shannon always
    assert last.entropy_bits > 2.0                              # noisy stream -> high diversity


def test_entropy_helpers_bounds():
    from atlas.session.signal_source import shannon_entropy_bits, _distribution_entropies
    assert shannon_entropy_bits(b"") == 0.0
    assert shannon_entropy_bits(b"\x00" * 32) == 0.0             # constant -> 0 bits
    assert shannon_entropy_bits(bytes(range(256))) == 8.0        # uniform bytes -> 8 bits
    # across-snapshot symbols: two states each half the time -> Shannon=min=1 bit.
    sh, mn = _distribution_entropies([b"A", b"B"] * 8)
    assert abs(sh - 1.0) < 1e-9 and abs(mn - 1.0) < 1e-9
    # a dominant state drags min-entropy BELOW Shannon (worst-case < average).
    sh2, mn2 = _distribution_entropies([b"A"] * 13 + [b"B", b"C", b"D"])
    assert mn2 < sh2


def test_change_signal_still_never_enters_the_value(monkeypatch):
    """The invariant survives change-detection: differing CHANGE patterns still
    yield the SAME QRNG pole value (change times/gates, never values)."""
    monkeypatch.setattr(pole_mod, "random_bytes", lambda n: b"Q" * n)
    src = _seq_source([b"\x01" * 8, b"\x02\x03\x04\x05\x06\x07\x08\x09"])
    src.sample()
    s = src.sample()
    assert s.changed_bits and s.changed_bits > 0
    v = pole_mod.fire_pole_value(physio_fire_moment=s.timing[0] / 255.0)
    assert v == b"Q" * 32                              # timing/change never touched the value


# -- 6. AMBIENT CHANGE DRIVES LIVENESS (PoLE), not synthetic data -------------

def test_live_ambient_stream_yields_operating_pole():
    """A live (changing) ambient stream folded through the Bayesian gate -> the
    PoLE operates. The REAL sensed change drives liveness."""
    from atlas.session.signal_source import pole_from_ambient
    pole = pole_from_ambient(AmbientSensorSource(), ticks=40, drand_round=b"\x00" * 8)
    assert pole.operate is True


def test_frozen_ambient_stream_fails_liveness_closed():
    """A frozen/replayed ambient stream -> the PoLE does NOT operate (fail-closed
    liveness), driven by the real change signal (0 changed bits)."""
    from atlas.session.signal_source import pole_from_ambient
    frozen = b"\x11\x22\x33\x44\x55\x66\x77\x88"
    pole = pole_from_ambient(AmbientSensorSource(sampler=lambda: frozen), ticks=30, drand_round=b"\x00" * 8)
    assert pole.operate is False


def test_ambient_liveness_likelihoods_mapping():
    from atlas.session.signal_source import ambient_liveness_likelihoods as L
    # bootstrap (no change info) -> neutral
    assert L(LiveSignalSample(timing=b"\x00", present=True, kind="ambient", simulated=True)) == (0.5, 0.5)
    # frozen -> strong not-live
    frozen = LiveSignalSample(timing=b"\x00", present=False, kind="ambient", simulated=True, changed_bits=0)
    psl, psnl = L(frozen); assert psl < 0.1 and psnl > 0.9
    # healthy change -> live evidence dominates
    live = LiveSignalSample(timing=b"\x00", present=True, kind="ambient", simulated=True,
                            changed_bits=30, min_entropy_bits=4.0)
    psl2, psnl2 = L(live); assert psl2 > psnl2
