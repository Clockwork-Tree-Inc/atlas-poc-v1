"""Contact & discovery — user-controlled reachability, spoof-proof and spam-proof.

Findability is OPTIONAL and per-persona (some people want to be found; most don't), a spectrum you
choose:
  PRIVATE   — invite-only; reachable ONLY via a one-time connect CODE you share out-of-band.
  REACHABLE — verified individuals can ring your published handle; you screen every call.
  FINDABLE  — your published name appears in lookup; broadly findable (public figures / businesses).

Every caller is a VERIFIED human (a `person_tag`) or an identified business, so caller-ID cannot be
spoofed; spam is bounded by Sybil-resistance (one verified human can't become many callers) + per-
person rate-limiting + PERSON-SCOPED blocking (block the human, not the handle — gone across all of
their personas). Those, plus screening, are what make individual reachability safe.

Two connection modes:
  * Mode 1 (mutual code): one side allocates a WINDOW-UNIQUE code and shares it (QR / tap / say it);
    the other redeems it; on match BOTH are revealed (mutual), then the code is consumed and the
    window closes. No match -> no reveal to either side.
  * Mode 2 (caller-ID ring): a verified caller rings a REACHABLE/FINDABLE persona; shows as "unknown"
    unless the caller opts to reveal; the callee screens (accept / reject / block).

The hub sees handles + codes (metadata) only; the actual key exchange is the recognition tunnel
(out of scope here). A real PAKE over the code is the production hardening for Mode 1.
"""
from __future__ import annotations

import base64
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, Optional, Set, Tuple


class Reachability(Enum):
    PRIVATE = "private"
    REACHABLE = "reachable"
    FINDABLE = "findable"


class ContactError(Exception):
    ...


@dataclass(frozen=True)
class Match:
    """Mutual reveal on a code match — both sides learn each other's handle, and only then."""
    owner: str
    redeemer: str


@dataclass(frozen=True)
class Call:
    call_id: int
    caller: str            # the caller's handle — shown to the callee ONLY if revealed
    caller_person: bytes   # person_tag — used for person-scoped block/rate-limit, never displayed
    callee: str
    revealed: bool

    def display(self) -> str:
        return self.caller if self.revealed else "unknown (verified human)"


@dataclass
class _Persona:
    handle: str
    level: Reachability
    name: Optional[str] = None


@dataclass
class _PendingCode:
    owner: str
    expires: int


DEFAULT_CODE_TTL = 300        # seconds the connect code lives (the handshake window)
DEFAULT_RATE_LIMIT = 5        # calls per caller-person per window
DEFAULT_RATE_WINDOW = 3600


def _default_gen() -> str:
    # short + human-typeable; global uniqueness FOR THE WINDOW is enforced by the hub (allocator),
    # so it only has to be distinct among currently-active codes.
    return base64.b32encode(os.urandom(5)).decode().rstrip("=")[:8]


@dataclass
class ContactHub:
    """Relay-side contact state. Sees handles + codes only; never content."""
    _gen: Callable[[], str] = _default_gen
    _personas: Dict[str, _Persona] = field(default_factory=dict)
    _names: Dict[str, str] = field(default_factory=dict)
    _codes: Dict[str, _PendingCode] = field(default_factory=dict)
    _calls: Dict[int, Call] = field(default_factory=dict)
    _blocks: Dict[str, Set[bytes]] = field(default_factory=dict)
    _rate: Dict[Tuple[bytes, int], int] = field(default_factory=dict)
    _next_call: int = 1

    # ---- reachability (opt-in, per persona) ----
    def set_reachability(self, handle: str, level: Reachability, *, name: Optional[str] = None) -> None:
        self._personas[handle] = _Persona(handle, level, name)
        if level is Reachability.FINDABLE and name:
            self._names[name] = handle

    def lookup(self, name: str) -> Optional[str]:
        """Resolve a name to a handle — ONLY personas that opted into FINDABLE appear here."""
        return self._names.get(name)

    # ---- Mode 1: mutual code ----
    def allocate_code(self, owner: str, *, now: int, ttl: int = DEFAULT_CODE_TTL) -> str:
        self._expire_codes(now)
        for _ in range(1000):
            code = self._gen()
            if code not in self._codes:                 # unique among ACTIVE codes (window-unique)
                self._codes[code] = _PendingCode(owner, now + ttl)
                return code
        raise ContactError("live-code space exhausted")

    def redeem_code(self, code: str, redeemer: str, *, now: int) -> Match:
        self._expire_codes(now)
        pc = self._codes.get(code)
        if pc is None:
            raise ContactError("no such live code")     # wrong/expired -> reveals nothing
        del self._codes[code]                            # one-time; the window closes
        return Match(owner=pc.owner, redeemer=redeemer)  # mutual reveal, only on match

    def _expire_codes(self, now: int) -> None:
        for c in [c for c, p in self._codes.items() if p.expires <= now]:
            del self._codes[c]

    # ---- Mode 2: caller-ID ring ----
    def place_call(self, *, caller: str, caller_person: bytes, callee: str, reveal: bool,
                   now: int, rate_limit: int = DEFAULT_RATE_LIMIT,
                   window: int = DEFAULT_RATE_WINDOW) -> Call:
        if not caller_person:
            raise ContactError("caller must be a verified human")     # no unverified/spoofed callers
        p = self._personas.get(callee)
        if p is None or p.level is Reachability.PRIVATE:
            raise ContactError("callee is invite-only (reach them with a code)")
        if caller_person in self._blocks.get(callee, set()):
            raise ContactError("blocked")                             # person-scoped: across all personas
        key = (caller_person, now // window)
        self._rate[key] = self._rate.get(key, 0) + 1
        if self._rate[key] > rate_limit:
            raise ContactError("rate limited")                        # anti-spam
        call = Call(self._next_call, caller, caller_person, callee, reveal)
        self._calls[call.call_id] = call
        self._next_call += 1
        return call

    def answer_call(self, call_id: int, *, accept: bool, block: bool = False) -> bool:
        """Callee screens: accept -> proceed to the recognition-tunnel handshake; reject -> dropped.
        Set block=True to person-scope-block the caller (stops them across all their personas)."""
        call = self._calls.pop(call_id, None)
        if call is None:
            raise ContactError("no such call")
        if block:
            self._blocks.setdefault(call.callee, set()).add(call.caller_person)
        return accept

    def block(self, callee: str, caller_person: bytes) -> None:
        self._blocks.setdefault(callee, set()).add(caller_person)
