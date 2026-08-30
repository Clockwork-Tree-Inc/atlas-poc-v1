"""Offline, deterministic drand-compatible beacon (§3.2 public beacon).

`api.drand.sh` is unreachable from the sealed build/CI environment (egress
policy), and a public beacon must be reproducible for tests anyway. LocalBeacon
produces drand-shaped rounds from a fixed genesis + period: round number
advances with wall-clock time and each round's randomness is
H(chain_seed || round). This is the *demonstrated, not trusted* public root the
spec calls for (§3.2 "the real root remains drand — demonstrated, not trusted").

On the Mac, swap in `drand.DrandHTTPBeacon` for the real League-of-Entropy chain;
both satisfy the `Beacon` protocol.
"""

from __future__ import annotations

import math

from .base import BeaconRound
from ..crypto.primitives import sha256


class LocalBeacon:
    period_s: float

    def __init__(self, *, genesis_time: float = 0.0, period_s: float = 3.0,
                 chain_seed: bytes = b"atlas-local-drand"):
        if period_s <= 0:
            raise ValueError("period must be positive")
        self.genesis_time = genesis_time
        self.period_s = period_s
        self.chain_seed = chain_seed

    def round_number_at(self, t: float) -> int:
        # drand convention: round 1 begins at genesis.
        if t < self.genesis_time:
            return 0
        return 1 + math.floor((t - self.genesis_time) / self.period_s)

    def _round(self, n: int) -> BeaconRound:
        rnd = sha256(self.chain_seed, n.to_bytes(8, "big"))
        return BeaconRound(round=n, randomness=rnd, signature=b"")

    def round_at(self, t: float) -> BeaconRound:
        return self._round(self.round_number_at(t))

    def latest(self, now: float) -> BeaconRound:
        return self.round_at(now)
