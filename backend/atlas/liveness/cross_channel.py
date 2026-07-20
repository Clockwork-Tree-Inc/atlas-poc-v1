"""Cross-channel coherence — the pulse must show up in more than one sensor at once.

A live heartbeat appears in THREE places on the ring: the PPG pulse rate, the HRV
intervals, and the accelerometer BALLISTOCARDIOGRAM (the tiny wrist recoil each beat).
On a living finger these agree. A replay that fakes the PPG waveform but cannot produce
a phase/rate-aligned accel BCG FAILS coherence — and faking every channel coherently is
exponentially harder than faking one. Optional living-band checks (SpO2, skin temp) add
cheap independent gates.

HONEST BOUNDARY: rate agreement is a necessary, not sufficient, anti-spoof — a
sophisticated rig that drives a real coherent BCG is, by construction, reproducing live
physiology. This raises spoof cost; it is not a proof of unspoofability. Feeds the GBSS
liveness gate; MEASURES to gate — never enters a key.
"""

from __future__ import annotations

import statistics as st
from typing import Optional, Sequence

# Living bands (finger). None on a channel = "not available", skipped (graceful degrade).
SPO2_BAND = (90.0, 100.0)
SKIN_TEMP_BAND_C = (28.0, 37.0)
DEFAULT_TOL_BPM = 8.0


def dominant_rate_bpm(waveform: Sequence[float], fs: float, *,
                      lo_bpm: float = 40.0, hi_bpm: float = 200.0) -> Optional[float]:
    """Dominant periodicity in the physiological band, via autocorrelation. Returns bpm,
    or None if there is no clear periodic component (flat / aperiodic → no pulse)."""
    n = len(waveform)
    if n < 8 or fs <= 0:
        return None
    m = st.mean(waveform)
    x = [v - m for v in waveform]
    ac0 = sum(v * v for v in x)
    if ac0 <= 0:
        return None                              # flat -> no pulse
    lo_lag = max(1, int(fs * 60.0 / hi_bpm))
    hi_lag = min(n - 1, int(fs * 60.0 / lo_bpm))
    if hi_lag <= lo_lag:
        return None
    best_lag, best_ac = None, 0.0
    for lag in range(lo_lag, hi_lag + 1):
        ac = sum(x[i] * x[i + lag] for i in range(n - lag))
        if ac > best_ac:
            best_ac, best_lag = ac, lag
    # require a real peak (a decent fraction of zero-lag energy), else it's noise.
    if best_lag is None or best_ac < 0.3 * ac0:
        return None
    return 60.0 * fs / best_lag


def pulse_coherence(ppg: Sequence[float], accel: Sequence[float], fs: float, *,
                    tol_bpm: float = DEFAULT_TOL_BPM) -> bool:
    """True iff the PPG and the accelerometer BCG BOTH show a physiological pulse AND
    their rates agree within `tol_bpm`. A flat/aperiodic/mismatched accel fails."""
    ppg_bpm = dominant_rate_bpm(ppg, fs)
    bcg_bpm = dominant_rate_bpm(accel, fs)
    if ppg_bpm is None or bcg_bpm is None:
        return False
    return abs(ppg_bpm - bcg_bpm) <= tol_bpm


def _in_band(v: Optional[float], band) -> bool:
    return v is None or (band[0] <= v <= band[1])   # None = channel absent -> don't block


def cross_channel_live(ppg: Sequence[float], accel: Sequence[float], fs: float, *,
                       spo2: Optional[float] = None, skin_temp_c: Optional[float] = None,
                       tol_bpm: float = DEFAULT_TOL_BPM) -> bool:
    """Full cross-channel liveness: PPG<->BCG pulse coherence, plus any available vitals
    in their living bands. Fail-closed on any present-and-out-of-band channel."""
    if not pulse_coherence(ppg, accel, fs, tol_bpm=tol_bpm):
        return False
    if not _in_band(spo2, SPO2_BAND):
        return False
    if not _in_band(skin_temp_c, SKIN_TEMP_BAND_C):
        return False
    return True
