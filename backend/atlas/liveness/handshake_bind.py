"""Enrolment handshake bind — the "handshake" that welds identity + liveness + co-location
into ONE gesture on ONE timestamp. Stateless, one-shot, nothing stored.

At enrolment the phone shows a RANDOM number N. Holding the phone in the same hand that
wears the ring, the user taps the ring on the phone N times while Face ID authenticates.
Each tap is a sharp mechanical impulse that BOTH IMUs — and the phone microphone — register
at the same instant. That binds three facts to one moment:

  * Face ID    -> WHO   (the identity on the phone)
  * live pulse -> ALIVE (from the ring; checked separately)
  * N co-occurring tap impulses on phone-IMU + ring-IMU (+ mic), at the Face-ID instant
    -> SAME BODY, LIVE, RIGHT NOW  (co-location + a fresh, unreplayable challenge)

`requested_n` is the system's random challenge: the taps must MATCH it, be mutually
time-aligned across channels (one physical impact seen by every sensor), and fall in the
window around the Face-ID success instant. Discrete taps beat a continuous shake — the
phone is still between impacts so Face ID can lock, and counting matched spikes is more
robust than a correlation floor. MEASURES to gate — never a key/value.

HONEST BOUNDARY: needs the ring to stream its IMU. The Colmi R10's accel stream is
intermittent, so on the R10 this degrades to pulse-only and the tap bind can't run — it is
the real thing for an IMU-streaming / secure-element ring. Detection thresholds are tunable
and calibrated per device.
"""
from __future__ import annotations

from typing import List, Optional, Sequence


def detect_taps(signal: Sequence[float], *, fs: float, threshold: float,
                refractory_s: float = 0.12) -> List[float]:
    """Impulse onset times (seconds) from a 1-D motion-magnitude (or audio-energy) signal:
    upward threshold crossings, with a refractory gap so one tap isn't double-counted."""
    times: List[float] = []
    last = -1e9
    dt = 1.0 / fs
    for i in range(1, len(signal)):
        t = i * dt
        if signal[i] >= threshold and signal[i - 1] < threshold and (t - last) >= refractory_s:
            times.append(t)
            last = t
    return times


def _aligned(a: Sequence[float], b: Sequence[float], tol_s: float) -> bool:
    """Bijection: every impulse in `a` has a distinct partner in `b` within `tol_s`."""
    if len(a) != len(b):
        return False
    used = [False] * len(b)
    for ta in a:
        hit = -1
        for j, tb in enumerate(b):
            if not used[j] and abs(ta - tb) <= tol_s:
                hit = j
                break
        if hit < 0:
            return False
        used[hit] = True
    return True


def verify_handshake(*, phone_taps: Sequence[float], ring_taps: Sequence[float],
                     requested_n: int, faceid_at_s: float,
                     mic_taps: Optional[Sequence[float]] = None,
                     window_s: float = 6.0, align_tol_s: float = 0.08) -> bool:
    """True iff the random-N tap challenge was met live and co-located:
      * exactly `requested_n` taps on the phone AND the ring (and mic, if provided),
      * every phone tap co-occurs with a ring tap (and mic tap) within `align_tol_s`
        (one physical impact seen by every channel — same hand / same contact),
      * all taps fall within +/- `window_s` of the Face-ID success instant.
    Fail-closed: any mismatch -> False."""
    if requested_n <= 0:
        return False
    if len(phone_taps) != requested_n or len(ring_taps) != requested_n:
        return False
    lo, hi = faceid_at_s - window_s, faceid_at_s + window_s
    if any(not (lo <= t <= hi) for t in list(phone_taps) + list(ring_taps)):
        return False
    if not _aligned(phone_taps, ring_taps, align_tol_s):
        return False
    if mic_taps is not None:
        if len(mic_taps) != requested_n or not _aligned(phone_taps, mic_taps, align_tol_s):
            return False
    return True
