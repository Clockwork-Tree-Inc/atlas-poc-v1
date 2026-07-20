"""Presence-fired Server-QRNG — the Living Key (LK) stand-in (§3.1, §3.2).

Roles (§3.1):
  * The QRNG is a single entropy source, NOT on demand. It is fired by the
    aggregate of device arrival-timing; the timing TIMES the firing (schedule).
  * §3.2: the private beacon (LK) is "the presence-fired Server-QRNG stand-in".

CORRECTED principle (§2.3): timing TIMES the firing; it NEVER enters the value.
The LK value is a CLEAN QRNG output (a fresh entropy core, hashed with the epoch)
— the inter-arrival timing digest is NOT mixed into the value bytes; it only sets
WHEN the QRNG next fires (`next_sampling_offset_s`). Forward secrecy comes from
the fresh core per firing plus the ratchet chain, not from committing timing into
the value. (`timing_commitment` is retained on the draw for scheduling/audit, not
as key material.)

This stand-in returns *timed randomness only* (§3.2 #3 / params): each device
composes its own session key locally; the server never holds a finished session
key.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from ..crypto.primitives import H, random_bytes, sha256


@dataclass
class ArrivalTiming:
    """Aggregate device arrival timestamps observed for one firing window."""

    timestamps: List[float] = field(default_factory=list)

    def inter_arrivals(self) -> List[float]:
        ts = sorted(self.timestamps)
        return [round(b - a, 6) for a, b in zip(ts, ts[1:])]

    def digest(self) -> bytes:
        # Quantise to milliseconds so the commitment is reproducible across the
        # two devices that observed the same arrivals.
        deltas = self.inter_arrivals()
        buf = b"".join(int(round(d * 1000)).to_bytes(8, "big", signed=True) for d in deltas)
        return H(b"atlas/interarrival", buf)


@dataclass(frozen=True)
class TimedDraw:
    """Timed randomness returned by the QRNG (the LK contribution for an epoch)."""

    drand_round: bytes
    randomness: bytes        # the entropy each device folds into its session key
    timing_commitment: bytes  # H(inter-arrival pattern) bound into the draw
    next_sampling_offset_s: float  # output "times the next sampling" (§3.1)


class ServerQRNG:
    """Single entropy source on the Mac (TrueRNG optional, OS CSPRNG adequate)."""

    def __init__(self, *, base_period_s: float = 3.0):
        self.base_period_s = base_period_s
        self._fire_count = 0

    def fire(self, arrival: ArrivalTiming, drand_round: bytes,
             *, entropy_core: bytes | None = None) -> TimedDraw:
        """Fire once, driven by aggregate arrival timing.

        The firing is *not on demand*: callers pass the arrival timing that
        triggered it. Per the corrected §2.3 principle, the arrival timing only
        TIMES the firing (the next-sampling schedule); it does NOT enter the value.
        The LK value is a CLEAN QRNG output from the fresh entropy core.

        `entropy_core` is normally drawn fresh from the CSPRNG. It is injectable
        ONLY so a test can hold the core constant and prove the inter-arrival
        timing does NOT change the value (timing times the firing, not the bytes).
        Production never passes it.
        """
        self._fire_count += 1
        core = entropy_core if entropy_core is not None else random_bytes(32)
        timing = arrival.digest()
        # THE PRINCIPLE (§2.3, corrected): timing TIMES the firing; it does NOT
        # enter the value. The LK value is a CLEAN QRNG output (core), never a
        # function of the timing digest. The aggregate arrival timing's only role
        # is to drive WHEN the QRNG fires (the next-sampling schedule below).
        randomness = sha256(b"atlas/qrng/value", core, drand_round)
        # The arrival timing "times the next sampling": jitter the next firing
        # window by the aggregate arrival pattern (a schedule input, not a value).
        jitter = (timing[0] / 255.0) * self.base_period_s
        return TimedDraw(
            drand_round=drand_round,
            randomness=randomness,
            timing_commitment=timing,   # retained for the schedule/audit, NOT in the value
            next_sampling_offset_s=self.base_period_s + jitter,
        )
