"""Swappable live-signal source — the external physical timing/gating input.

THE ROLE (Locked Model §2.3, unchanged invariant): a live physical signal
TIMES the QRNG draws and GATES/advances the ratchet ("is the signal present
right now?"). It is NEVER folded into a key/value. "Biology times; QRNG values."

This module makes that external signal a SWAPPABLE SOURCE so the pipeline is
source-agnostic:

    pipeline  <--  SignalSource.sample() -> LiveSignalSample(timing, present)

  * `AmbientSensorSource` — the iPhone-only PoC source: the phone's fused
    multimodal ambient stream (mic / accelerometer / gyro / magnetometer /
    barometer / camera-noise / light) TIMES and GATES. It STANDS IN for the ring
    (ambient-not-biological) — `simulated=True`. On device the real sensor reads
    happen in Swift (AtlasApp/Ambient); this Python model is the reference and is
    driven by an injectable sampler for deterministic tests.

  * `RingSignalSource` — the R10 ring's streamed biological continuity signal.
    DEFERRED in this build; present only to prove the swap point. Swapping ambient
    -> ring is a SOURCE swap, no pipeline rewiring.

LOAD-BEARING INVARIANT (enforced by construction + tests):
  `LiveSignalSample.timing` feeds ONLY scheduling — `RatchetClock.next_interval`
  (WHEN the next tick fires) and the PoLE fire moment. It must NEVER reach an
  HKDF/value. The VALUE stays clean QRNG (`fire_pole_value`, `random_bytes`).
  `test_signal_source.py` proves timing bytes never change a derived key.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Deque, Optional, Sequence

# Canonical entropy operators (single source of truth — also used by the GBSS
# entropy vector). Re-exported here for callers/tests that import from this module.
from ..liveness.entropy import distribution_entropies as _distribution_entropies
from ..liveness.entropy import shannon_entropy_bits
# The R10 ring's sensor-sample model (PPG-derived HR/HRV/SpO2 + accel). Used by the
# now-wired RingSignalSource.
from ..liveness.synthetic import SensorSample

# Default fused-sample width (bytes) for the simulated ambient stream.
_AMBIENT_WINDOW = 8
# A fused window with fewer than this many non-zero (live) bytes reads as
# "signal absent" -> the gate closes (fail-closed). A flatlined stream is dead.
_LIVE_FLOOR = 2
# CHANGE-DETECTION (§ ambient: change, not level). Each snapshot is XOR'd against
# the previous one; a live sensor flips >= this many bits every tick (raw — noise
# and everything). A FROZEN or replayed-identical snapshot flips ZERO -> fail-closed.
_CHANGE_FLOOR = 1
# Coprime weights spread the changed-bit pattern across a full 0..255 schedule byte.
_TIMING_WEIGHTS = (997, 631, 271, 4099, 5003, 211, 83, 149)
# Entropy ACROSS SNAPSHOTS (each snapshot is a symbol; the buffer is the recent
# sequence of room-states). Two measures on that symbol distribution:
#   * SHANNON  (avg unpredictability) — the liveness-QUALITY signal, reported and
#     fed to the Bayes gate.
#   * MIN-ENTROPY (-log2 max p; worst-case) — the conservative, adversarial measure
#     NIST uses. It tanks the moment ONE state dominates (a near-frozen feed with
#     occasional blips), so it is the HARD anti-loop gate.
# Both max out at log2(_ENTROPY_HISTORY) bits for genuine noise (all snapshots
# distinct) and collapse toward 0 for a short A,B,A,B loop (which XOR alone waves
# through, since each frame differs from the last). The HARD gate applies only when
# the buffer is FULL (fixed window -> stable threshold). Catches SHORT (~<=5 frame)
# loops; a long replayed recording needs the ring's biological coherence. Floors
# want on-device tuning; min-entropy would be replaced by a proper estimator if this
# is ever made a hard security claim (this is a liveness gate, not an RNG).
_ENTROPY_HISTORY = 16                      # buffer of snapshots -> max entropy 4 bits
_ENTROPY_WARM = 4                          # report once this many buffered
_MIN_ENTROPY_FLOOR_BITS = 2.5              # hard gate (catches <=~5-frame loops)


def _popcount(data: bytes) -> int:
    return sum(bin(b).count("1") for b in data)


def _spread_delta(delta: bytes) -> int:
    """Fold the XOR-delta into one well-spread schedule byte (0..255). The jitter is
    driven by CHANGE, never by absolute level. Schedule only — never a value."""
    mix = 0
    for i, d in enumerate(delta):
        mix += d * _TIMING_WEIGHTS[i % len(_TIMING_WEIGHTS)]
    return mix % 256


class SignalSourceUnavailable(Exception):
    """The requested signal source is not wired in this build (e.g. the deferred
    R10 ring source under the AMBIENT_SIGNAL_SOURCE build)."""


@dataclass(frozen=True)
class LiveSignalSample:
    """One live sample from a physical signal source.

    `timing` is a WHEN — it drives the ratchet cadence and the QRNG fire moment
    and is NEVER folded into a value. `present` is the live gate ("is the signal
    here right now?"). `simulated` is loud on purpose: ambient stands in for the
    biological anchor, so nothing downstream can silently claim biological
    liveness.
    """

    timing: bytes            # >=1 byte; scheduling only, never key material
    present: bool            # the live "signal present right now" gate
    kind: str                # "ambient" | "ring" | ...
    simulated: bool          # True = stand-in (not coherent living biology)
    channels: tuple = field(default_factory=tuple)   # contributing channels (log)
    # Liveness telemetry (measurements for gating only — NEVER value material):
    changed_bits: Optional[int] = None       # popcount(this XOR previous snapshot)
    entropy_bits: Optional[float] = None     # Shannon across snapshots (None until warm)
    min_entropy_bits: Optional[float] = None # min-entropy across snapshots (the hard gate)


class SignalSource(ABC):
    """A source of a live physical timing/gating signal. The pipeline consumes
    ONLY this interface, so ambient (now) and ring (later) are interchangeable."""

    kind: str = "abstract"
    simulated: bool = True

    @abstractmethod
    def sample(self) -> LiveSignalSample:
        """Return a FRESH sample, pulled ON-DEMAND per ratchet tick (B4) — NOT a
        continuous background stream the tick dips into. Called once per
        prospective tick to (a) time the interval and (b) test the presence gate.
        Fresh-per-tick matches the no-cache invariant and resists replay."""
        raise NotImplementedError


class AmbientSensorSource(SignalSource):
    """iPhone ambient multimodal stream as the timing/gating source (STAND-IN for
    the ring; `simulated=True`).

    The phone samples as many ambient channels as available (mic included) and
    FUSES them into a live window — a snapshot of "the room right now" as bytes.
    PRESENCE and TIMING come from how that snapshot CHANGES, not its absolute level:

      * XOR vs the PREVIOUS snapshot (raw — noise and everything). A live sensor
        flips bits every tick; a FROZEN/replayed-identical snapshot flips ZERO ->
        gate closes (fail-closed). Anything CONSTANT (a steady hum, gravity, the
        room's baseline loudness) cancels in the XOR, so absolute level stops
        mattering — only change does. `changed_bits` = popcount(delta).
      * `timing` — a schedule byte derived from the changed-bit PATTERN (jitter
        driven by real change). Schedule only; never a value.
      * Windowed Shannon entropy over recent snapshots — a liveness QUALITY signal
        that also catches a short A,B,A,B replay LOOP (which XOR alone waves through
        because each frame differs from the last). A too-degenerate stream
        (constant, or tiny loop) hard-fails; the estimate also rides along
        (`entropy_bits`) for the Bayesian liveness gate.

    First tick BOOTSTRAPS (no previous to diff against): it gates on window
    liveness alone; change-detection begins on the next tick.

    LOAD-BEARING INVARIANT: XOR delta, popcount, and entropy are MEASUREMENTS used
    ONLY to time/gate — none is ever folded into a key/value. The value stays clean
    QRNG.

    `sampler()` returns the fused raw window (on device: the real sensor fusion;
    in tests: an injected deterministic function). Returning a flatlined/empty
    window, or the SAME window twice, models signal loss/replay -> the gate closes.
    """

    kind = "ambient"
    simulated = True

    # The multimodal channels the phone fuses (declared for honest logging; the
    # actual reads are in the Swift AmbientSensorSource on device).
    DEFAULT_CHANNELS = (
        "microphone", "accelerometer", "gyroscope", "magnetometer",
        "barometer", "camera_noise", "ambient_light",
    )

    def __init__(self, *, sampler: Optional[Callable[[], bytes]] = None,
                 channels: Sequence[str] = DEFAULT_CHANNELS,
                 live_floor: int = _LIVE_FLOOR, change_floor: int = _CHANGE_FLOOR,
                 min_entropy_floor_bits: float = _MIN_ENTROPY_FLOOR_BITS):
        # Default sampler: a simulated live ambient window. os.urandom stands in
        # for real sensor variability (this is the explicit ambient STAND-IN).
        import os
        self._sampler = sampler or (lambda: os.urandom(_AMBIENT_WINDOW))
        self._channels = tuple(channels)
        self._live_floor = live_floor
        self._change_floor = change_floor
        self._min_entropy_floor = min_entropy_floor_bits
        self._prev: Optional[bytes] = None
        self._history: Deque[bytes] = deque(maxlen=_ENTROPY_HISTORY)

    def sample(self) -> LiveSignalSample:
        window = self._sampler()
        live_bytes = sum(1 for b in window if b != 0)
        window_live = live_bytes >= self._live_floor
        prev, self._prev = self._prev, window
        if window:
            self._history.append(window)

        # BOOTSTRAP: first comparable tick has no previous snapshot. Gate on window
        # liveness alone; timing from the raw window head. Change-detection begins
        # next tick.
        if prev is None or len(prev) != len(window) or not window:
            timing = window[:1] if window else b""
            return LiveSignalSample(timing=timing, present=window_live, kind=self.kind,
                                    simulated=True, channels=self._channels)

        # CHANGE-DETECTION: XOR this snapshot against the previous (raw; noise and
        # everything). Baseline cancels -> only change survives. A frozen/replayed
        # identical snapshot flips ZERO bits -> not present (fail-closed).
        delta = bytes(a ^ b for a, b in zip(window, prev))
        changed = _popcount(delta)

        # Entropy ACROSS SNAPSHOTS (symbols): Shannon (quality, reported) + min-
        # entropy (worst-case, the hard anti-loop gate). Reported once warm; the
        # min-entropy HARD gate applies only when the buffer is FULL (fixed window
        # -> stable threshold; a partial window would false-fail genuine noise).
        warm = len(self._history) >= _ENTROPY_WARM
        shannon = min_entropy = None
        if warm:
            shannon, min_entropy = _distribution_entropies(list(self._history))
        full = len(self._history) == self._history.maxlen
        entropy_ok = (min_entropy >= self._min_entropy_floor) if (full and min_entropy is not None) else True

        present = window_live and changed >= self._change_floor and entropy_ok
        timing = bytes([_spread_delta(delta)])
        return LiveSignalSample(timing=timing, present=present, kind=self.kind,
                                simulated=True, channels=self._channels,
                                changed_bits=changed, entropy_bits=shannon,
                                min_entropy_bits=min_entropy)


def ambient_liveness_likelihoods(sample: LiveSignalSample, *,
                                 window_bits: int = _AMBIENT_WINDOW * 8) -> tuple[float, float]:
    """Map one ambient sample's CHANGE + entropy telemetry to Bayesian
    (p_s_given_live, p_s_given_not_live) for the LivenessGate — so the REAL sensed
    change DRIVES liveness (not synthetic data). Evidence only; never a value.

      * bootstrap tick (no previous to diff) -> neutral (0.5, 0.5);
      * gated-out (`present` False: frozen, flatlined, or a degenerate loop caught
        by the FULL-buffer min-entropy gate) -> strong NOT-live (0.02, 0.98);
      * otherwise graded: more change -> stronger live evidence (genuine noise
        flips ~half the bits -> saturates near 0.98).

    Keys off `sample.present` for the degenerate decision (rather than re-deriving
    from min-entropy) so it inherits the SAME full-buffer logic — a small warm-up
    buffer makes even genuine noise look low-entropy, which must NOT read as dead.
    """
    if sample.changed_bits is None:
        return 0.5, 0.5
    if not sample.present:
        return 0.02, 0.98
    frac = sample.changed_bits / window_bits          # ~0.5 for noise, 0 for frozen
    live = min(0.5 + frac, 0.98)
    return live, 1.0 - live


def pole_from_ambient(source: SignalSource, *, ticks: int, drand_round: bytes,
                      sensor_digest: bytes = b"ambient"):
    """Fold `ticks` ambient samples through a Bayesian LivenessGate into a PoLE, so
    the PoLE liveness reflects the REAL ambient change. A live (changing) stream ->
    operate True; a frozen/looped stream -> operate False (fail-closed liveness).
    This replaces the synthetic liveness stream the device PoLE used as a stand-in."""
    from ..liveness.bayes import LivenessGate
    gate = LivenessGate()
    for _ in range(ticks):
        psl, psnl = ambient_liveness_likelihoods(source.sample())
        gate.update(p_s_given_live=psl, p_s_given_not_live=psnl)
    return gate.state(sensor_digest=sensor_digest, drand_round=drand_round)


# The ring's IMU also gates on-body presence: a worn ring on a live wrist always has
# physiological micro-tremor; a REMOVED ring (on a table) reads near-zero motion.
# Below this, the ring is not on a body -> not coherent (catches removal AND a
# replayed pulse fed to a motionless ring — the on-body anti-spoof).
_RING_REMOVED_ACCEL = 0.005


def _ring_coherent(s: SensorSample) -> bool:
    """A plausible LIVING pulse ON A BODY: HR in human range, real beat-to-beat HRV,
    AND the ring's IMU showing on-body micro-movement. A flat HRV (screen replay),
    out-of-range HR, OR a motionless ring (removed / on a table / replayed pulse on a
    still ring) is not coherent."""
    return (40.0 <= s.hr <= 200.0 and s.hrv_ms >= 10.0
            and s.accel_mag >= _RING_REMOVED_ACCEL)


class RingSignalSource(SignalSource):
    """The R10 ring's streamed biological continuity signal — the coherent-living-
    biology anchor. Now WIRED: it consumes a ring sampler (the real R10 on device, or
    an injected `SensorSample` stream in tests) and produces the SAME
    `LiveSignalSample` the ambient source does, so it drops into the pipeline with NO
    rewiring — the source swap the architecture promised.

    `simulated=False` — this is the REAL coherent-biology anchor, not the ambient
    stand-in (that flag flips honestly). A removed/absent ring (sampler -> None) or an
    incoherent pulse (flat HRV / spoof) reads as signal ABSENT -> gate closes
    (fail-closed) — this is the liveness-break signal the ambient build lacked. With
    NO sampler it RAISES (refuses to fake biology), preserving honest deferral.

    INVARIANT: the biological signal TIMES and GATES; it never enters a key/value.
    """

    kind = "ring"
    simulated = False

    def __init__(self, *, sampler: Optional[Callable[[], Optional[SensorSample]]] = None):
        self._sampler = sampler

    def sample(self) -> LiveSignalSample:
        if self._sampler is None:
            raise SignalSourceUnavailable(
                "no ring wired — refusing to fake biology; inject a ring sampler "
                "(real R10 on device, or a SensorSample stream in tests)")
        s = self._sampler()
        if s is None or not _ring_coherent(s):
            # removed / disconnected / incoherent (flat HRV, spoof) -> absent, gate closed
            return LiveSignalSample(timing=b"", present=False, kind=self.kind, simulated=False)
        # timing from beat-to-beat biological jitter (schedule only, never a value).
        timing = bytes([int(s.hrv_ms * 3 + s.hr) % 256])
        return LiveSignalSample(timing=timing, present=True, kind=self.kind, simulated=False)


@dataclass(frozen=True)
class TimedTick:
    """Result of a source-driven ratchet step. `gated_out=True` means the live
    gate was closed (no signal present) and no advance happened (fail-closed)."""

    tick: object                     # ContinuityTick when it ran, else None
    interval_s: float
    gated_out: bool
    source_kind: str
    simulated: bool


def timed_ratchet_step(device, source: SignalSource, *, pole, drand_round: bytes,
                       beacon: bytes, challenge: bytes = b"") -> TimedTick:
    """Drive ONE ratchet step from ANY SignalSource. Source-agnostic: swapping
    the ambient source for the ring source needs NO change here.

      1. sample the live signal;
      2. if not present -> gate closed -> fail-closed inert (no advance);
      3. else the sample TIMES the interval (schedule only) and the existing
         continuity ratchet runs (value = clean QRNG + fresh beacon, unchanged).
    """
    s = source.sample()
    if not s.present:
        return TimedTick(tick=None, interval_s=0.0, gated_out=True,
                         source_kind=s.kind, simulated=s.simulated)
    interval_s = device.next_ratchet_interval(bio_signal=s.timing)   # WHEN, not value
    tick = device.continuity_tick(pole, drand_round=drand_round, beacon=beacon,
                                  challenge=challenge)
    return TimedTick(tick=tick, interval_s=interval_s, gated_out=False,
                     source_kind=s.kind, simulated=s.simulated)
