"""Phone <-> ring cross-referencing — the same-body binding.

The phone and the ring each have an IMU. If they are on the SAME live person, their
motion streams share the body's movement (walking, gestures) and therefore CORRELATE —
at a small lag, to allow for clock/transport offset. If the ring is detached (on a table)
or on a DIFFERENT body, the correlation collapses. So one cheap check does two jobs:

  * anti-spoof — a replayed/idle ring that isn't actually moving with you fails,
  * same-body binding — it ties THIS ring to THIS phone to ONE live body, defeating
    "ring on person A, phone on person B" farming.

An attacker must now fake MUTUALLY-CORRELATED motion across two devices, not one stream.

HONEST BOUNDARY: wrist vs pocket see the same motion through different transfer paths, so
correlation is strong but not 1.0; the floor is a tunable heuristic, calibrated on real
MotionSense streams here and to be re-tuned on-device. Feeds the GBSS coherence gate;
MEASURES to gate — never enters a key.
"""

from __future__ import annotations

import statistics as st
from typing import Sequence


def _pearson(a: Sequence[float], b: Sequence[float]) -> float:
    n = min(len(a), len(b))
    if n < 3:
        return 0.0
    a, b = a[:n], b[:n]
    ma, mb = st.mean(a), st.mean(b)
    va = sum((x - ma) ** 2 for x in a)
    vb = sum((y - mb) ** 2 for y in b)
    if va <= 0 or vb <= 0:
        return 0.0
    cov = sum((a[i] - ma) * (b[i] - mb) for i in range(n))
    return cov / (va ** 0.5 * vb ** 0.5)


def cross_correlation(phone: Sequence[float], ring: Sequence[float], *, max_lag: int = 5) -> float:
    """Best Pearson correlation over small lags (-max_lag..max_lag) — tolerant of a slight
    timing offset between the two devices' streams. Returns the max (same-body motion is
    positively correlated)."""
    phone = [float(x) for x in phone]
    ring = [float(x) for x in ring]
    best = -1.0
    for lag in range(-max_lag, max_lag + 1):
        if lag >= 0:
            c = _pearson(phone[lag:], ring[:len(ring) - lag] if lag else ring)
        else:
            c = _pearson(phone[:lag], ring[-lag:])
        best = max(best, c)
    return best


# Calibrated on real MotionSense streams: same-body (shared motion + independent sensor
# noise) sits well above this; a detached/idle ring or a different body sits well below.
SAME_BODY_FLOOR = 0.4


def same_body(phone: Sequence[float], ring: Sequence[float], *,
              floor: float = SAME_BODY_FLOOR, max_lag: int = 5) -> bool:
    """True iff the phone and ring streams move together enough to be one live body.
    Fail-closed: a detached ring, an idle/flat ring, or a different person -> False."""
    return cross_correlation(phone, ring, max_lag=max_lag) >= floor
