"""Independent per-device ratchet cadence — 10s ± BIOLOGICAL jitter (§5.3, §16).

Every clock = a regular base period + biological jitter. The device ratchet's
jitter within [nominal ± jitter] is derived from the enrolled ring's live sensor
signal (the same stream that times the PoLE draw) — NOT from an RNG, NOT a fixed
schedule.

THE PRINCIPLE (§2.3): the biological signal determines a SCHEDULE offset (WHEN
the next tick fires) — a timing value, exactly like the server LK clock's
next-sampling offset. It is NEVER folded into key material; putting the signal's
bytes (or the interval) into a value would be physiology/timing-in-a-value
(forbidden, §8/§23). The clock is a scheduler of WHEN, never a source of key
bytes.

Two devices see different biological streams, so their ticks desynchronise
(independent cadence / population decorrelation) — now from biology, not an RNG.
"""

from __future__ import annotations

from ..params import RATCHET_NOMINAL_S, RATCHET_JITTER_S


class RatchetClock:
    """Per-device biologically-jittered cadence for the continuity ratchet.

    Each device owns ONE clock and times it from its own live ring signal, so two
    devices drift apart immediately (independent cadence). Intervals fall in
    [nominal - jitter, nominal + jitter]; where in that band is set by the
    biological sample — a WHEN, never a value.
    """

    def __init__(self, *, nominal_s: float = RATCHET_NOMINAL_S,
                 jitter_s: float = RATCHET_JITTER_S):
        if jitter_s < 0:
            raise ValueError("jitter must be non-negative")
        if jitter_s >= nominal_s:
            raise ValueError("jitter must be smaller than the nominal period")
        self.nominal_s = nominal_s
        self.jitter_s = jitter_s
        self._last_interval_s: float | None = None

    def next_interval(self, *, bio_signal: bytes) -> float:
        """Time the next interval within [nominal ± jitter] from the enrolled
        ring's live signal. `bio_signal` is a fresh sensor sample; a sample byte
        maps to a schedule offset in the jitter band (the same mapping the server
        LK clock uses on the arrival digest). This is a WHEN — it is NOT folded
        into any key and carries no key material."""
        if not bio_signal:
            raise ValueError("biological signal required to time the ratchet clock")
        frac = bio_signal[0] / 255.0                       # live sample -> [0,1]
        interval_s = (self.nominal_s - self.jitter_s) + frac * (2.0 * self.jitter_s)
        self._last_interval_s = interval_s
        return interval_s

    @property
    def last_interval(self) -> float | None:
        return self._last_interval_s
