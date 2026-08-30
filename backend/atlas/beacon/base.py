"""Beacon interface shared by the real drand client and the offline stand-in."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class BeaconRound:
    """An external-drand round — Atlas's BOOTSTRAP / defence-in-depth anchor
    (§3.2, XV §2.2), NOT the epoch key (that is `beacon.epoch.EpochRound`).

    Mirrors a drand round: a monotonically increasing round number and the
    round's public randomness. `signature` is present for the real drand chain
    and empty for the deterministic offline stand-in. Before the aggregator's
    epoch beacon has fired, this round's index doubles as the epoch round
    (bootstrap); thereafter it is used only as an anchor.
    """

    round: int
    randomness: bytes
    signature: bytes = b""

    def epoch_round(self) -> bytes:
        """The 8-byte round index, in the same shape as `EpochRound.epoch_round()`
        so a bootstrap round is a drop-in epoch-round label."""
        return self.round.to_bytes(8, "big")


class Beacon(Protocol):
    """Public periodic beacon (drand-shaped) — the bootstrap / anchor source."""

    period_s: float

    def round_at(self, t: float) -> BeaconRound:
        """The beacon round active at wall-clock time `t` (seconds)."""
        ...

    def latest(self, now: float) -> BeaconRound:
        ...
