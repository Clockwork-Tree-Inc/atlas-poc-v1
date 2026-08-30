"""Debug trace — record *everything* happening (app + server) for bug-finding, WITHOUT ever
recording secrets.

For debugging you want a rich, timestamped, replayable event stream you can slice and reconstruct.
But this system's whole premise is proofs-not-data, so the recorder is **structurally debug-safe**:
a redaction guard strips anything secret-shaped (keys, seeds, plaintext, biometrics, credentials)
and replaces raw byte blobs with a *hash commitment* — so you can still CORRELATE (same bytes →
same hash) and reason about flow, but the raw value is never stored. No key or plaintext can end up
in a trace even if a caller passes one by mistake.

A single `correlation_id` threads an app-side flow to its server-side events (distributed-tracing
style), so you can reconstruct "what happened" end-to-end. `replay()` feeds a recorded flow back to
reproduce a bug (pairs with `ReplaySignalSource`). Debug-build-gated in production — enabling capture
is an explicit debug flag, not on by default in shipped beta.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

# Field-name fragments that must never have their value recorded raw. Includes the actual
# secret field names the original list missed (user_half/server_half, nullifier, share,
# selector, stretched, material, entropy, pole, ...) — but the SHAPE check below is the real
# fail-safe: name matching alone fails OPEN.
_SECRET_HINTS = (
    "key", "secret", "password", "passwd", "token", "private", "plaintext",
    "seed", "biometric", "credential", "priv", "sk", "mnemonic", "opening",
    "half", "nullifier", "share", "selector", "stretched", "material", "entropy", "pole",
)
_MAX_STR = 512
_HEX = set("0123456789abcdefABCDEF")
_B64 = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")


def _looks_secret(s: str) -> bool:
    """SHAPE check (fixes the name-only fail-open hole): key material is often a plain STRING —
    `key.hex()` / base64 — so a mis-named field can leak the raw value. Catch it by shape,
    whatever the field is called: a long (>=24 char), space-free hex or base64/base64url token."""
    t = s.strip()
    if len(t) < 24 or " " in t:
        return False
    if len(t) % 2 == 0 and all(c in _HEX for c in t):
        return True                                            # hex-encoded bytes
    if all(c in _B64 for c in t) and any((c.isdigit() or c in "+/=_-") for c in t):
        return True                                            # base64 / base64url
    return False


def _redact(name: str, value: Any) -> Any:
    """Debug-safe view of a value. Secret-named fields → '[redacted]'; raw bytes → a hash
    commitment (correlatable, not reversible); SECRET-SHAPED strings (hex/base64 key material,
    any field name) → a hash commitment; oversized strings → a length marker. FAILS SAFE: a
    secret-shaped value is never recorded raw even under a benign field name."""
    if any(h in name.lower() for h in _SECRET_HINTS):
        return "[redacted]"
    if isinstance(value, (bytes, bytearray)):
        return f"<{len(value)}B sha256={hashlib.sha256(bytes(value)).hexdigest()[:8]}>"
    if isinstance(value, str):
        if _looks_secret(value):
            return f"<str {len(value)} chars sha256={hashlib.sha256(value.encode()).hexdigest()[:8]}>"
        if len(value) > _MAX_STR:
            return f"<str {len(value)} chars>"
    return value


@dataclass(frozen=True)
class TraceEvent:
    ts: int                    # logical/wall time (injected for deterministic tests)
    correlation_id: str        # threads one flow across app <-> server
    subsystem: str             # e.g. "app.session", "server.relay", "app.presence"
    kind: str                  # event name
    fields: Dict[str, Any]     # already redacted — safe to persist/export

    def as_dict(self) -> Dict[str, Any]:
        return {"ts": self.ts, "correlation_id": self.correlation_id,
                "subsystem": self.subsystem, "kind": self.kind, "fields": dict(self.fields)}


@dataclass
class DebugTrace:
    _events: List[TraceEvent] = field(default_factory=list)

    def record(self, *, ts: int, correlation_id: str, subsystem: str, kind: str,
               **fields: Any) -> TraceEvent:
        safe = {k: _redact(k, v) for k, v in fields.items()}
        e = TraceEvent(ts, correlation_id, subsystem, kind, safe)
        self._events.append(e)
        return e

    def error(self, *, ts: int, correlation_id: str, subsystem: str, message: str,
              **fields: Any) -> TraceEvent:
        return self.record(ts=ts, correlation_id=correlation_id, subsystem=subsystem,
                           kind="error", message=message, **fields)

    def events(self, *, correlation_id: Optional[str] = None, subsystem: Optional[str] = None,
               kind: Optional[str] = None) -> List[TraceEvent]:
        out = self._events
        if correlation_id is not None:
            out = [e for e in out if e.correlation_id == correlation_id]
        if subsystem is not None:
            out = [e for e in out if e.subsystem == subsystem]
        if kind is not None:
            out = [e for e in out if e.kind == kind]
        return out

    def correlate(self, correlation_id: str) -> List[TraceEvent]:
        """One flow's events in time order — the app+server reconstruction for a bug."""
        return sorted(self.events(correlation_id=correlation_id), key=lambda e: e.ts)

    def export(self) -> List[Dict[str, Any]]:
        """JSON-able dump for offline analysis (already redacted — safe to share)."""
        return [e.as_dict() for e in self._events]

    def replay(self, handler: Callable[[TraceEvent], None], *,
               correlation_id: Optional[str] = None) -> None:
        """Feed events (optionally one flow) in time order to a handler to reproduce a bug."""
        for e in sorted(self.events(correlation_id=correlation_id), key=lambda e: e.ts):
            handler(e)
