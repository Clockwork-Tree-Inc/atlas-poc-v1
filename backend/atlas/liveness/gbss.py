"""GBSS entropy vector — the structured liveness/context entropy (Math Spec v1.4).

The spec divides liveness assessment into a vector of entropy channels:

    h_i = heart-rate-variance entropy   (PPG / GSR / HRV — involuntary biomechanical)
    s_i = motion-variance entropy       (IMU)
    m_i = micro-interaction entropy      (touch, keystroke, voice)
    c_i = contextual / environmental     (ambient)

"Entropy from liveness is the core; contexts of living are added." Each channel is
scored by the entropy OPERATORS (Shannon, Lempel-Ziv complexity, spectral entropy —
see entropy.py) into a per-channel density in [0,1], then aggregated into a
per-window liveness density that feeds the PoLE gate.

PHONE vs RING (honest boundary): the PHONE produces s_i (IMU) and c_i (ambient),
plus partial m_i (voice/mic now; touch/keystroke are labeled hooks). h_i is the
INVOLUNTARY biomechanical core — a living body cannot stop its HRV/PPG — and comes
from the R10 RING (deferred). On the phone, h_i is None and the vector is honestly
marked ring-deferred; the density aggregates only the channels actually present.

LOAD-BEARING INVARIANT: every density here is a MEASUREMENT of liveness/freshness.
It only TIMES and GATES the ratchet (feeds the Bayesian PoLE gate); it is NEVER
folded into a key/value. The value stays clean QRNG. (Re-proven by test.)
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

from .entropy import distribution_entropies, lempel_ziv_complexity, spectral_entropy
from .synthetic import SensorSample

# Density below this reads as degenerate (constant / replay loop / too-low
# diversity) -> strong NOT-live. Wants on-device tuning.
_DENSITY_FLOOR = 0.15


def channel_density(*, waveform: Optional[Sequence[float]] = None,
                    symbols: Optional[Sequence[bytes]] = None) -> float:
    """Score one channel's liveness density in [0,1] from its raw samples, combining
    whichever operators the data supports:
      * a symbol sequence (e.g. quantized snapshots, keystroke gaps) -> normalized
        Shannon (diversity) + Lempel-Ziv complexity (anti-loop);
      * a waveform (e.g. mic/IMU/PPG time-series) -> spectral entropy (structure).
    Genuine live signal -> high; constant / looped / degenerate -> low."""
    scores: List[float] = []
    if symbols:
        shannon, _min = distribution_entropies(symbols)
        max_bits = math.log2(len(symbols)) if len(symbols) > 1 else 1.0
        scores.append(min(shannon / max_bits, 1.0) if max_bits > 0 else 0.0)
        if all(isinstance(s, (bytes, bytearray)) for s in symbols):
            scores.append(min(lempel_ziv_complexity(b"".join(symbols)), 1.0))
    if waveform is not None and len(waveform) >= 4:
        scores.append(spectral_entropy(waveform))
    return sum(scores) / len(scores) if scores else 0.0


@dataclass
class EntropyVector:
    """One window's GBSS entropy densities. `h_i` is None on the phone (ring-
    deferred); the aggregate covers only the channels actually present."""

    s_i: float                          # motion variance (IMU) — phone
    c_i: float                          # contextual/environmental (ambient) — phone
    m_i: Optional[float] = None         # micro-interaction (touch/keystroke/voice) — phone partial
    h_i: Optional[float] = None         # HRV/PPG/GSR (involuntary) — RING (deferred)

    def present(self) -> Dict[str, float]:
        return {k: v for k, v in
                {"h_i": self.h_i, "s_i": self.s_i, "m_i": self.m_i, "c_i": self.c_i}.items()
                if v is not None}

    def ring_deferred(self) -> bool:
        return self.h_i is None

    def density(self) -> float:
        """Aggregate liveness density over the PRESENT channels (mean). h_i, when
        the ring lands, simply raises coverage — the shape is unchanged."""
        vals = list(self.present().values())
        return sum(vals) / len(vals) if vals else 0.0


def ring_h_i(window: Sequence[SensorSample]) -> float:
    """h_i — the INVOLUNTARY biomechanical entropy the R10 ring provides (the GBSS
    core the phone cannot produce). Scored over a window of the HRV series: a healthy
    living heart has COMPLEX beat-to-beat variability (high entropy); a flat /
    metronomic / spoofed / removed pulse is low.

    Two physiological facts, blended: (1) AMPLITUDE — a healthy heart's beat-to-beat
    HRV is tens of ms; a flat/spoofed pulse is single-digit (entropy alone can't see
    this, because tiny noise still looks 'flat-spectrum' high). (2) COMPLEXITY — the
    interval series is non-metronomic. h_i is low unless BOTH hold.

    HONEST BOUNDARY: a spoof that replays genuine high-amplitude, complex HRV is NOT
    defeated by this score — that residual rests on the ring's own on-body anti-spoof,
    not here."""
    if len(window) < 4:
        return 0.0
    hrv_series = [s.hrv_ms for s in window]
    mean_hrv = sum(hrv_series) / len(hrv_series)
    amplitude = min(mean_hrv / 40.0, 1.0)          # healthy HRV saturates ~40ms; flat -> ~0
    q = [bytes([min(int(x), 255)]) for x in hrv_series]
    complexity = channel_density(waveform=hrv_series, symbols=q)
    return 0.5 * amplitude + 0.5 * complexity      # both must hold


def ring_s_i(window: Sequence[SensorSample]) -> float:
    """s_i from the ring's OWN IMU — on-wrist motion, more body-bound than the phone's
    (the phone can sit on a table while the ring is on a live wrist). Same amplitude+
    complexity blend as h_i: a live wrist has real, complex micro-movement; a still /
    removed ring is near-zero flat motion (its tiny jitter must not read as live)."""
    if len(window) < 4:
        return 0.0
    accel = [s.accel_mag for s in window]
    mean_accel = sum(accel) / len(accel)
    amplitude = min(mean_accel / 0.03, 1.0)                 # ~0.03g active micro-motion
    q = [bytes([min(int(a * 1000), 255)]) for a in accel]   # accel ~0.001-0.05 -> 1-50
    complexity = channel_density(waveform=accel, symbols=q)
    return 0.5 * amplitude + 0.5 * complexity


def fuse_motion_s_i(phone_s_i: float, ring_window: Optional[Sequence[SensorSample]]) -> float:
    """Fuse phone motion with the ring's on-wrist motion. The ring is on-body, so it
    is weighted higher; with no ring, s_i is the phone's alone (unchanged)."""
    if ring_window is None or len(ring_window) < 4:
        return phone_s_i
    return 0.6 * ring_s_i(ring_window) + 0.4 * phone_s_i     # on-body ring weighted higher


def entropy_vector_with_ring(*, s_i: float, c_i: float, m_i: Optional[float] = None,
                             ring_window: Optional[Sequence[SensorSample]] = None) -> EntropyVector:
    """Build the GBSS vector from the ring when present: h_i from HRV (the involuntary
    core), AND s_i FUSED with the ring's own IMU (on-wrist motion). Both involuntary
    channels come from the wrist. Ring absent -> h_i deferred (None) and s_i is the
    phone's alone. The ring lands -> coverage rises; shape unchanged."""
    h = ring_h_i(ring_window) if (ring_window is not None and len(ring_window) >= 4) else None
    fused_s_i = fuse_motion_s_i(s_i, ring_window)
    return EntropyVector(s_i=fused_s_i, c_i=c_i, m_i=m_i, h_i=h)


def gbss_liveness_likelihoods(vector: EntropyVector, *,
                              density_floor: float = _DENSITY_FLOOR) -> tuple[float, float]:
    """Map a GBSS entropy vector's density to Bayesian (p_s_given_live,
    p_s_given_not_live) for the PoLE gate. Degenerate (below floor) -> strong
    not-live; otherwise graded by density. Evidence only; never a value."""
    d = vector.density()
    if d < density_floor:
        return 0.02, 0.98
    live = min(0.5 + d * 0.48, 0.98)
    return live, 1.0 - live


def pole_from_gbss(vectors: Sequence[EntropyVector], *, drand_round: bytes,
                   sensor_digest: bytes = b"gbss"):
    """Fold a sequence of per-window GBSS vectors through the Bayesian LivenessGate
    into a PoLE. Live (high-density) windows -> operate; degenerate windows ->
    fail-closed. The RICHER liveness the two-phone run gates on."""
    from .bayes import LivenessGate
    gate = LivenessGate()
    for v in vectors:
        psl, psnl = gbss_liveness_likelihoods(v)
        gate.update(p_s_given_live=psl, p_s_given_not_live=psnl)
    return gate.state(sensor_digest=sensor_digest, drand_round=drand_round)
