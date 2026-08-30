"""Scoped capability tokens (§2.3).

Token = MAC(SessKey, { scope, purpose, expiry, nonce }).

"No keys are ever issued to the interface layer; in Tier 3 the boundary is
enforced inside the app between the enclave-resident authority and the UI"
(§2.3). The token is the only thing that crosses that boundary: a scoped,
expiring capability, not a key.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import threading
from dataclasses import dataclass

from ..crypto.primitives import random_bytes


@dataclass(frozen=True)
class CapabilityToken:
    scope: str
    purpose: str
    expiry: float       # epoch index or wall-clock; compared by the verifier
    nonce: str          # hex
    mac: str = ""       # hex; filled by issue()

    def _payload(self) -> bytes:
        body = {"scope": self.scope, "purpose": self.purpose,
                "expiry": self.expiry, "nonce": self.nonce}
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def issue(sess_key: bytes, *, scope: str, purpose: str, expiry: float) -> CapabilityToken:
    nonce = random_bytes(16).hex()
    tok = CapabilityToken(scope=scope, purpose=purpose, expiry=expiry, nonce=nonce)
    mac = hmac.new(sess_key, tok._payload(), hashlib.sha256).hexdigest()
    return CapabilityToken(scope=scope, purpose=purpose, expiry=expiry, nonce=nonce, mac=mac)


def verify(sess_key: bytes, token: CapabilityToken, *, now: float,
           scope: str | None = None, purpose: str | None = None) -> bool:
    expected = hmac.new(sess_key, token._payload(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, token.mac):
        return False
    # Fail closed on non-finite expiry/clock: `now > nan` is False in IEEE-754,
    # so a NaN expiry would otherwise mint a never-expiring token (and a NaN clock
    # would accept any expired token).
    if not math.isfinite(now) or not math.isfinite(token.expiry):
        return False
    if now > token.expiry:
        return False
    if scope is not None and token.scope != scope:
        return False
    if purpose is not None and token.purpose != purpose:
        return False
    return True


class ReplayCache:
    """Single-use enforcement for capability tokens (§2.3 / T-02).

    `verify()` is stateless: MAC + TTL + scope only, so a captured token can be
    replayed any number of times before it expires. For one-shot capabilities (a
    payment claim, a reward grant) wrap verification in a ReplayCache. The first
    successful presentation consumes the token's nonce; any later presentation of
    the same nonce is rejected even though the MAC and TTL still check out. This
    closes the replay-within-TTL gap.

    The cache keys on the token nonce. A presentation that fails `verify()`
    (bad MAC, expired, wrong scope) is never recorded, so an attacker cannot
    poison the cache with forged nonces.

    Memory is BOUNDED: a nonce only needs remembering until its token expires
    (after that `verify()` rejects it on TTL anyway), so expired entries are
    evicted on each call — the cache size tracks the number of live tokens, not
    the all-time count. Check-and-set is under a lock, so concurrent
    presentations of the same one-shot token cannot both win (no TOCTOU
    double-use even on a free-threaded interpreter). NOTE: state is per-instance/
    per-process; cross-node single-use needs a shared store (a DB unique
    constraint on the nonce), same as the nullifier rail.
    """

    def __init__(self) -> None:
        self._seen: dict[str, float] = {}      # nonce -> token expiry
        self._lock = threading.Lock()

    def verify_once(self, sess_key: bytes, token: CapabilityToken, *, now: float,
                    scope: str | None = None, purpose: str | None = None) -> bool:
        if not verify(sess_key, token, now=now, scope=scope, purpose=purpose):
            return False
        with self._lock:
            self._evict_expired(now)
            if token.nonce in self._seen:
                return False                   # replay: nonce already consumed
            self._seen[token.nonce] = token.expiry
            return True

    def _evict_expired(self, now: float) -> None:
        if not math.isfinite(now):
            return
        dead = [n for n, exp in self._seen.items() if now > exp]
        for n in dead:
            del self._seen[n]
