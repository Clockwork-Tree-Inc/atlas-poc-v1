"""Beacon interface shared by the real drand client and the offline stand-in."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class BeaconRound:
    """A public beacon round — the epoch key (§3.2, XV §2.2).

    Mirrors a drand round: a monotonically increasing round number and the
    round's public randomness. `signature` is present for the real drand chain
    and empty for the deterministic offline stand-in.
    """

    round: int
    randomness: bytes
    signature: bytes = b""

    def drand_round(self) -> bytes:
        return self.round.to_bytes(8, "big")


class Beacon(Protocol):
    """Public periodic beacon (drand-shaped)."""

    period_s: float

    def round_at(self, t: float) -> BeaconRound:
        """The beacon round active at wall-clock time `t` (seconds)."""
        ...

    def latest(self, now: float) -> BeaconRound:
        ...
