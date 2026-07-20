"""Live-presence session lifecycle with resumption codes.

Presence is the ring's live pulse. A live session is NOT binary — a Bluetooth blip must
not nuke it, but an actual removal, a timeout, or a ring-SWAP across a gap must. Three
states:

  PRESENT   — live pulse; the presence gate is open.
  SUSPENDED — the ring dropped; within a bounded grace window the session HOLDS (gate
              closed, live keys not yet wiped). On reconnect the ring must present the
              next RESUMPTION CODE to prove it is the SAME ring that was continuously
              present — not a swapped-in ring that merely also has a pulse.
  LOCKED    — grace window expired, OR a wrong/absent code, OR explicit removal: hard
              lockdown (the caller wipes the live layer, keeps the sealed identity) and
              records an optional forensic event. TERMINAL — re-presence is a new session.

Resumption codes are a one-time chain off the handshake-bind shared secret established at
enrolment (Face ID + live pulse + random-N tap, all on one timestamp). Both the ring and
the phone derive `code_i = HKDF(bind, "atlas/resume|i")` independently; a swapped/spoofed
ring lacks `bind` and cannot produce it, and the counter strictly advances so a captured
old code is rejected (replay-resistant).

No wall clock: times are passed in (`at_s`), so this is deterministic and testable. It
GATES/TIMES the session — the codes authenticate continuity, never a key/value.

HONEST HARDWARE BOUNDARY: this needs a ring that can STORE + PRESENT codes (challenge-
response / secure element). The Colmi R10 is a dumb sensor ring (streams PPG/accel, no
app-writable secret) — on it, SUSPENDED is APPROXIMATED by BLE bond + resumed pulse
coherence + the window, which does NOT cryptographically exclude a swap across the gap.
The code protocol is the real thing for a secure-element ring; the R10 runs the approx.
"""
from __future__ import annotations

import hmac
from dataclasses import dataclass
from enum import Enum

from ..crypto.primitives import hkdf

RESUME_INFO = b"atlas/resume"
DEFAULT_GRACE_S = 30.0   # how long a dropped ring may be gone before hard lockdown


def resume_code(bind_secret: bytes, counter: int, *, length: int = 16) -> bytes:
    """The one-time resumption code for reconnect #counter — HKDF off the bind secret.
    Ring and phone derive it independently; a ring without `bind_secret` cannot."""
    return hkdf(ikm=bind_secret, info=RESUME_INFO + b"|" + str(counter).encode(), length=length)


class PresenceState(Enum):
    PRESENT = "present"
    SUSPENDED = "suspended"
    LOCKED = "locked"


@dataclass(frozen=True)
class LockEvent:
    """Emitted on a LOCKED transition — the caller may seal it into the forensic ledger.
    `reason` distinguishes a real break from a mere reconnect (which emits nothing)."""
    reason: str          # "removed" | "timeout" | "bad_code"
    at_s: float


class PresenceSession:
    """The live-presence state machine. Fail-closed by construction: anything that isn't a
    verified same-ring resume within the window ends in LOCKED."""

    def __init__(self, bind_secret: bytes, *, at_s: float, grace_s: float = DEFAULT_GRACE_S) -> None:
        if not bind_secret:
            raise ValueError("bind_secret required (from the enrolment handshake)")
        self._bind = bind_secret
        self._grace_s = grace_s
        self._state = PresenceState.PRESENT
        self._counter = 0                       # next expected resumption-code index
        self._last_seen_s = at_s
        self._suspended_at: float | None = None
        self._lock_event: LockEvent | None = None

    @property
    def state(self) -> PresenceState:
        return self._state

    @property
    def lock_event(self) -> LockEvent | None:
        return self._lock_event

    def operating(self) -> bool:
        """Is the presence gate open right now? (Only in PRESENT.)"""
        return self._state == PresenceState.PRESENT

    def pulse(self, at_s: float) -> None:
        """A fresh live pulse was observed on the ring. No effect once LOCKED (terminal)."""
        if self._state == PresenceState.LOCKED:
            return
        self._state = PresenceState.PRESENT
        self._last_seen_s = at_s
        self._suspended_at = None

    def disconnect(self, at_s: float) -> None:
        """The ring dropped / pulse lost — enter the grace window (do NOT wipe yet)."""
        if self._state == PresenceState.PRESENT:
            self._state = PresenceState.SUSPENDED
            self._suspended_at = at_s

    def check_timeout(self, at_s: float) -> bool:
        """Call while SUSPENDED: lock if the grace window has elapsed. True iff it locked."""
        if (self._state == PresenceState.SUSPENDED and self._suspended_at is not None
                and (at_s - self._suspended_at) > self._grace_s):
            self._lock("timeout", at_s)
            return True
        return False

    def reconnect(self, code: bytes, at_s: float) -> bool:
        """The ring reconnected and presents a resumption code. Returns True (RESUMED) iff
        SUSPENDED, still within the grace window, and the code matches the next expected
        one. Otherwise LOCKS (fail-closed)."""
        if self._state != PresenceState.SUSPENDED or self._suspended_at is None:
            return False
        if (at_s - self._suspended_at) > self._grace_s:
            self._lock("timeout", at_s)
            return False
        expected = resume_code(self._bind, self._counter)
        if not hmac.compare_digest(code, expected):
            self._lock("bad_code", at_s)        # wrong/absent code — a swap or a spoof
            return False
        self._counter += 1                       # one-time: advance so this code can't replay
        self._state = PresenceState.PRESENT
        self._last_seen_s = at_s
        self._suspended_at = None
        return True

    def remove(self, at_s: float) -> None:
        """Explicit removal (or a decision to hard-lock now). Terminal."""
        self._lock("removed", at_s)

    def _lock(self, reason: str, at_s: float) -> None:
        self._state = PresenceState.LOCKED
        self._suspended_at = None
        self._lock_event = LockEvent(reason=reason, at_s=at_s)
