"""Per-epoch pseudonym rotation + differential privacy (Real-ID spec §6, T-20).

Closes the T-20 gap: the system had per-CONTEXT handles but not per-EPOCH
rotation. A child derives a fresh pseudonym each epoch, forward from the child +
epoch, so the on-the-wire identifier changes every epoch and the same child is
not trivially linkable across epochs:

    epoch_pseudonym = Derive(child, drand_round)   — fresh per epoch

Preserve inheritance + uniqueness: the rotating pseudonyms still descend from the
same verified System-ID for accountability (the authority can still resolve a
presented verification token under cause), while being mutually unlinkable to an
observer.

DP treatment: a network observer also sees side-channels (activity counts,
timing). Rotating the identifier alone is not enough — apply a differential-
privacy mechanism (Laplace) to any aggregate/observable so cross-epoch
correlation via side-channels is bounded.
"""

from __future__ import annotations

import math
import random
import secrets
from dataclasses import dataclass

from ..crypto.primitives import H
from ..keys.identity import Child


def epoch_pseudonym(child: Child, drand_round: bytes) -> bytes:
    """Fresh, unlinkable-across-epochs handle for this child this epoch.

    Forward from the child's secret + epoch; an observer cannot link two epochs'
    pseudonyms, and cannot derive the child or System-ID from one (one-way H)."""
    secret = child.keypair.ed_sk.private_bytes_raw()
    return H(b"atlas/epoch-pseudonym", secret, drand_round)


@dataclass
class DPCounter:
    """A differential-privacy-treated observable (e.g. per-epoch activity count).

    Adds Laplace noise calibrated to sensitivity/epsilon so the released value
    bounds what an observer learns, capping cross-epoch correlation via the
    side-channel. epsilon is the privacy parameter (smaller = more private).
    """

    epsilon: float = 0.5
    sensitivity: float = 1.0

    def release(self, true_count: int, *, rng: random.Random | None = None) -> float:
        # Laplace(0, b) via inverse CDF; b = sensitivity / epsilon. Draw from a
        # CSPRNG by default (Mersenne-Twister state is recoverable, which would
        # let an adversary predict the noise); clamp u off the endpoints so
        # log(1-2|u|) never hits log(0) -> -inf. `rng` override is test-only.
        b = self.sensitivity / self.epsilon
        if rng is not None:
            u = rng.random() - 0.5
        else:
            u = (int.from_bytes(secrets.token_bytes(8), "big") / 2 ** 64) - 0.5
        u = max(-0.5 + 1e-12, min(0.5 - 1e-12, u))
        noise = -b * math.copysign(1.0, u) * math.log(1 - 2 * abs(u))
        return true_count + noise
