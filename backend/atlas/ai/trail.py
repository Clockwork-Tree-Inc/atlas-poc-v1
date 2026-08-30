"""Cryptographic provenance trail for the AI + content + rights flow — and the author-citation economy.

Every lifecycle step — access grant/revoke, content purchase+license, inference (model + sources +
human), output+citations — is appended as a HASH-CHAINED, tamper-evident event; the head can be
ANCHORED to the accountability log via a `LedgerBackend` (local now, PoLE-consensus chain later).
Only roots/commitments cross the anchor boundary — content stays private.

Grounded citations drive the AUTHOR ECONOMY: every source is attributed (always cite), and authors
who ALLOWED their work to be used get a per-use micropayment (closed-loop coin) plus the citation
record. So allowing use earns reads, citations, and payment — verifiably. It flips scrape-and-sue
into a fair, consented, compensated marketplace.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import FrozenSet, List, Optional

from ..economy.coin import Coin
from ..ledger.backend import LedgerBackend
from .seam import InferenceResult

_ZERO = b"\x00" * 32


def _h(*parts: bytes) -> bytes:
    m = hashlib.sha3_256()
    for p in parts:
        m.update(len(p).to_bytes(4, "big"))
        m.update(p)
    return m.digest()


def _i(n: int) -> bytes:
    return int(n).to_bytes(8, "big")


@dataclass(frozen=True)
class TrailEvent:
    kind: str          # grant | revoke | purchase | inference | output | citation
    actor: str         # who did it (human or agent handle)
    payload: bytes     # canonical commitment to the event detail (never raw content)
    prev: bytes

    def digest(self) -> bytes:
        return _h(b"atlas/ai-trail", self.kind.encode(), self.actor.encode(), self.payload, self.prev)


@dataclass
class ProvenanceTrail:
    _events: List[TrailEvent] = field(default_factory=list)

    def head(self) -> bytes:
        return self._events[-1].digest() if self._events else _ZERO

    def append(self, kind: str, actor: str, payload: bytes) -> TrailEvent:
        e = TrailEvent(kind, actor, payload, self.head())
        self._events.append(e)
        return e

    def events(self, kind: Optional[str] = None) -> List[TrailEvent]:
        return [e for e in self._events if kind is None or e.kind == kind]

    def verify_chain(self) -> bool:
        prev = _ZERO
        for e in self._events:
            if e.prev != prev:
                return False
            prev = e.digest()
        return True

    def anchor(self, backend: LedgerBackend, *, owner_id: bytes, epoch_round: bytes):
        """Anchor the trail head to the accountability log — immutable, tamper-evident timestamp."""
        return backend.publish(owner_id, self.head(), epoch_round)


# --- lifecycle recorders (commitments only; content stays private) ------------

def record_grant(trail: ProvenanceTrail, *, owner: str, agent: str, scope: str, expires: int):
    return trail.append("grant", owner, _h(agent.encode(), scope.encode(), _i(expires)))


def record_revoke(trail: ProvenanceTrail, *, owner: str, agent: str, scope: str):
    return trail.append("revoke", owner, _h(agent.encode(), scope.encode()))


def record_purchase(trail: ProvenanceTrail, *, buyer: str, item: bytes, license_terms: str):
    return trail.append("purchase", buyer, _h(item, license_terms.encode()))


def record_inference(trail: ProvenanceTrail, *, invoker: str, result: InferenceResult):
    src = b"".join(_h(s.item, s.author.encode()) for s in result.sources)
    return trail.append("inference", invoker, _h(result.model_hash, src))


def record_output(trail: ProvenanceTrail, *, invoker: str, result: InferenceResult):
    cites = b"".join(s.author.encode() for s in result.sources)
    return trail.append("output", invoker, _h(_h(result.output.encode()), cites))


# --- the author-citation economy ----------------------------------------------

@dataclass(frozen=True)
class Citation:
    author: str
    item: bytes
    paid: int          # per-use micropayment to the author (0 if not reward-eligible)


def cite_and_reward(trail: ProvenanceTrail, coin: Coin, result: InferenceResult, *, payer: str,
                    per_use_fee: int = 0, rewardable: FrozenSet[str] = frozenset()) -> List[Citation]:
    """Attribute EVERY grounded source (always cite), and pay a per-use micropayment to authors who
    ALLOWED their work to be used (`rewardable`). Records each as a citation event on the trail.
    Non-consenting authors' work never reaches here (filtered upstream by license/consent)."""
    cites: List[Citation] = []
    for s in result.sources:
        pay = per_use_fee if (s.author in rewardable and per_use_fee > 0) else 0
        if pay:
            coin.transfer(payer, s.author, pay)          # micropayment straight to the author
        trail.append("citation", payer, _h(s.author.encode(), s.item, _i(pay)))
        cites.append(Citation(s.author, s.item, pay))
    return cites
