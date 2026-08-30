"""Presentation-attack detection at capture (§8.2).

PAD runs at capture: a LiDAR depth-plane check (a screen reads as a flat plane)
plus texture/moiré analysis, catching the majority of screen replays. Strong
probabilistic detection, not proof (§0.2 "meaningfully better, not perfect").

This backend model operates on summary signals the capture app extracts on
device (it has no camera): a depth map (per-region distances from LiDAR) and a
moiré/periodicity score from texture analysis. A real 3-D scene has depth
variance well above a flat plane; a screen replay is near-planar and tends to
exhibit periodic moiré.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Sequence

from ..crypto.primitives import H

# A flat plane (screen) has near-zero depth variance. Threshold in metres^2.
DEPTH_VARIANCE_MIN = 0.01
# Moiré/periodicity score in [0,1]; screens tend high. Accept below this.
MOIRE_MAX = 0.6


class PADRejected(Exception):
    """Raised when capture fails PAD — the spoof is defeated at capture time."""


@dataclass(frozen=True)
class PADResult:
    passed: bool
    depth_variance: float
    moire_score: float
    reasons: tuple[str, ...] = field(default_factory=tuple)

    def digest(self) -> bytes:
        raw = f"{int(self.passed)}|{self.depth_variance:.6f}|{self.moire_score:.6f}"
        return H(b"atlas/pad", raw.encode())


def pad_check(*, depth_map: Sequence[float], moire_score: float) -> PADResult:
    """Run the depth-plane + moiré checks. `depth_map` is per-region distances
    (metres); `moire_score` is the texture-periodicity estimate in [0,1]."""
    if len(depth_map) < 4:
        return PADResult(False, 0.0, moire_score, ("insufficient depth samples",))
    variance = statistics.pvariance(depth_map)
    reasons = []
    flat = variance < DEPTH_VARIANCE_MIN
    moire = moire_score > MOIRE_MAX
    if flat:
        reasons.append(f"depth variance {variance:.4f} < {DEPTH_VARIANCE_MIN} (reads as a flat plane)")
    if moire:
        reasons.append(f"moiré score {moire_score:.2f} > {MOIRE_MAX} (periodic texture)")
    return PADResult(passed=not (flat or moire), depth_variance=variance,
                     moire_score=moire_score, reasons=tuple(reasons))
