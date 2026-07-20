"""Epoch-cap runtime guard (§3.2 / §4) — force a re-key when the beacon stalls.

The recognition value is CONSTANT within an epoch, so it is replayable until the beacon
advances (by design — that's the replay window). `EPOCH_LENGTH_CAP_S` bounds that window:
if the beacon has not advanced within the cap, the epoch is STALE and its recognition
value must not be reused — the runtime must force a re-key. Previously the cap was only a
parameter; this enforces it.

No wall clock: times are passed in (the codebase's no-`time.time()` discipline), so the
guard is deterministic and testable. It GATES/TIMES; it never enters key material.
"""

from __future__ import annotations

from ..params import EPOCH_LENGTH_CAP_S


class EpochStalled(Exception):
    """The beacon has not advanced within the cap: the recognition value is stale and
    must not be reused. Force a re-key (rotate / re-establish the epoch)."""


class EpochCapGuard:
    """Tracks the last beacon advance and enforces the epoch cap at each use."""

    def __init__(self, *, cap_s: float = EPOCH_LENGTH_CAP_S) -> None:
        self.cap_s = cap_s
        self._last_advance_s: float | None = None

    def beacon_advanced(self, at_s: float) -> None:
        """Record that the public beacon advanced (a fresh epoch) at time `at_s`."""
        self._last_advance_s = at_s

    def age_s(self, now_s: float) -> float | None:
        """Seconds since the last beacon advance, or None if it never advanced."""
        if self._last_advance_s is None:
            return None
        return now_s - self._last_advance_s

    def expired(self, now_s: float) -> bool:
        """True if the epoch is stale: never advanced, or beyond the cap since the last
        advance. Fail-closed — an un-bootstrapped guard is expired."""
        age = self.age_s(now_s)
        return age is None or age >= self.cap_s

    def check(self, now_s: float) -> None:
        """Raise EpochStalled if the epoch is stale at `now_s` (call before reusing a
        recognition value / continuing on the current epoch key)."""
        if self.expired(now_s):
            raise EpochStalled(
                f"beacon stalled: epoch age {self.age_s(now_s)} >= cap {self.cap_s}s "
                f"— force a re-key")
