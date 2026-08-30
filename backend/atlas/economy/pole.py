"""Proof of Living Entropy (PoLE) — the base participation proof of the economy.

A DEVICE collects entropy from the living universe (the "environ" — biological + ambient),
authorised by a LIVE, UNIQUE person, and emits a PoLE proof. Devices submit proofs to the
server, which AGGREGATES them per epoch; `economy.policy` then mints Atlas PoLE coin from the
aggregate. PoLE itself carries NO value and is NOT soul-bound — it is the proof-of-contribution
that issuance is computed from.

"Only a live unique person can mint": each proof binds a `person_tag` (the DLEQ-bound VRF
nullifier from `zk.person_tag`, unlinkable across personas) plus a liveness attestation. The
pool dedupes on (person_tag, epoch) so one human counts ONCE per epoch (Sybil-resistant),
carrying a uniform PRESENCE unit (→ UBI eligibility) and a variable ACTIVITY weight (→ variable
rewards; raised when a continuous-liveness wearable adds behaviour sensing).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional


class NotLiveError(Exception):
    """Raised when a PoLE mint is attempted without a live unique person (the mint gate)."""


@dataclass(frozen=True)
class PoLEProof:
    person_tag: bytes       # unique-person nullifier N (see zk.person_tag); the dedupe key
    epoch: int
    entropy_commit: bytes   # H(collected living/ambient entropy digest) — the "environ" proof
    activity_weight: int    # >=1; presence baseline = 1, raised by behaviour / continuous liveness

    def __post_init__(self) -> None:
        if self.activity_weight < 1:
            raise ValueError("activity_weight must be >= 1 (presence baseline)")


def collect_pole(person_tag: bytes, epoch: int, entropy_commit: bytes, *,
                 live: bool, activity_weight: int = 1) -> PoLEProof:
    """Emit a PoLE proof. Raises unless a LIVE unique person authorises it (the mint gate)."""
    if not live:
        raise NotLiveError("PoLE can only be minted by a live unique person")
    return PoLEProof(person_tag, epoch, entropy_commit, activity_weight)


@dataclass
class PoLEPool:
    """Server-side aggregation for one issuance run. Dedupes per (person_tag, epoch): one human
    counts once — re-submission keeps the HIGHEST activity weight, it never inflates presence."""
    _by_person: Dict[bytes, int] = field(default_factory=dict)  # person_tag -> activity_weight
    epoch: Optional[int] = None

    def add(self, proof: PoLEProof) -> None:
        if self.epoch is None:
            self.epoch = proof.epoch
        elif proof.epoch != self.epoch:
            raise ValueError("a pool aggregates a single epoch")
        prev = self._by_person.get(proof.person_tag, 0)
        self._by_person[proof.person_tag] = max(prev, proof.activity_weight)

    @property
    def persons(self) -> int:
        """Unique live persons this epoch — the uniform PRESENCE count (→ UBI)."""
        return len(self._by_person)

    @property
    def total_activity(self) -> int:
        """Sum of activity weights (→ variable-reward shares)."""
        return sum(self._by_person.values())

    def activity_of(self, person_tag: bytes) -> int:
        return self._by_person.get(person_tag, 0)

    def people(self) -> Dict[bytes, int]:
        return dict(self._by_person)
