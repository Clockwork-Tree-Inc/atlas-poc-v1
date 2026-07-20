"""Synthetic presence streams + adversarial spoof streams (§5.1, §11).

Tests the algorithm, not biology (§11 "Population logic ... Tests the algorithm,
not biology"). Models the R10's actual sensors (§5.1):
  * PPG: HR, HRV, SpO2 — living tissue, beating heart.
  * 3-axis accelerometer: micro-movement entropy; "stillness below physiological
    baseline is a spoof signal."

Each generator yields SensorSamples and a per-sample likelihood pair
(P(S|L), P(S|¬L)) for the Bayesian gate. A live human shows HR in range, genuine
beat-to-beat HRV, and micro-movement; a screen/replay spoof shows flat HRV and
sub-baseline stillness.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from random import Random
from typing import Iterator

from ..crypto.primitives import H

# Physiological baselines (resting adult).
HR_MIN, HR_MAX = 48.0, 110.0
HRV_LIVE_MS = 45.0          # healthy beat-to-beat variability
MICRO_MOTION_BASELINE = 0.012  # g; below this for too long => spoof signal


@dataclass(frozen=True)
class SensorSample:
    hr: float           # bpm
    hrv_ms: float       # beat-to-beat variability proxy
    spo2: float         # %
    accel_mag: float    # micro-movement magnitude (g, gravity removed)

    def digest(self) -> bytes:
        raw = f"{self.hr:.2f}|{self.hrv_ms:.2f}|{self.spo2:.1f}|{self.accel_mag:.4f}"
        return H(b"atlas/sensor", raw.encode())


def _likelihood(sample: SensorSample) -> tuple[float, float]:
    """Heuristic P(S|L), P(S|¬L) for one sample.

    Live signature: HR in physiological range, real HRV, micro-movement present.
    Spoof signature (screen replay / static): flat HRV and/or sub-baseline
    stillness. Returns clamped likelihoods.
    """
    hr_ok = HR_MIN <= sample.hr <= HR_MAX
    hrv_ok = sample.hrv_ms >= 15.0
    motion_ok = sample.accel_mag >= MICRO_MOTION_BASELINE
    spo2_ok = 90.0 <= sample.spo2 <= 100.0

    score = sum([hr_ok, hrv_ok, motion_ok, spo2_ok])
    # P(S|L): a live human almost always produces these; P(S|¬L): a spoof
    # rarely reproduces all of them simultaneously.
    p_s_given_live = {0: 0.05, 1: 0.2, 2: 0.5, 3: 0.85, 4: 0.97}[score]
    p_s_given_not_live = {0: 0.97, 1: 0.85, 2: 0.5, 3: 0.2, 4: 0.05}[score]
    return p_s_given_live, p_s_given_not_live


def live_stream(n: int = 40, *, seed: int = 1) -> Iterator[tuple[SensorSample, tuple[float, float]]]:
    rng = Random(seed)
    hr = 68.0
    for i in range(n):
        hr += rng.uniform(-2.5, 2.5)
        hr = max(HR_MIN + 3, min(HR_MAX - 3, hr))
        sample = SensorSample(
            hr=hr,
            hrv_ms=HRV_LIVE_MS + rng.uniform(-12, 12),
            spo2=97.5 + rng.uniform(-1.2, 1.2),
            accel_mag=MICRO_MOTION_BASELINE + abs(rng.gauss(0.01, 0.006)),
        )
        yield sample, _likelihood(sample)


def spoof_stream(n: int = 40, *, seed: int = 2) -> Iterator[tuple[SensorSample, tuple[float, float]]]:
    """Screen-replay / static spoof: plausible-looking HR but flat HRV and
    sub-baseline stillness (the accelerometer tells on it)."""
    rng = Random(seed)
    for i in range(n):
        sample = SensorSample(
            hr=72.0 + rng.uniform(-0.3, 0.3),   # suspiciously stable
            hrv_ms=3.0 + rng.uniform(-1, 1),    # flat HRV
            spo2=98.0,                          # constant
            accel_mag=0.001 + rng.uniform(0, 0.002),  # below baseline (still)
        )
        yield sample, _likelihood(sample)
