"""Bayesian liveness gate and PoLE state (§5.2).

  P(L|S) = P(S|L)·P(L) / [ P(S|L)·P(L) + P(S|¬L)·(1−P(L)) ]   P(L) ~ Beta(a0,b0)
  PoLE_state = H( P(L|S)_current || sensor_digest || epoch )    [no ring_SE_sig at Tier 3]

Operate if P(L|S) >= pi* (§5.2). Tier-3 note (§5.2): the canonical PoLE_state
(Math Spec §D.5) includes a ring_SE_sig term; the R10 cannot produce it, so the
Tier-3 digest omits it and the phone's enclave signature stands in (added by the
attestation subsystem). No raw biometric is transmitted — only proof objects.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterable

from ..crypto.primitives import H
from ..params import LIVENESS_PRIOR_A0, LIVENESS_PRIOR_B0, PI_STAR


@dataclass(frozen=True)
class PoLEState:
    p_live: float
    state_digest: bytes
    drand_round: bytes
    operate: bool


class LivenessGate:
    """Running Bayesian gate fed per-sample likelihoods.

    Each sample contributes a likelihood ratio via P(S|L) and P(S|¬L). The
    Beta(a0,b0) prior on P(L) is the personal reference accumulated during the
    calibration window (§6). The posterior from one sample becomes the prior for
    the next, so the gate integrates evidence over the stream.
    """

    def __init__(self, *, a0: float = LIVENESS_PRIOR_A0, b0: float = LIVENESS_PRIOR_B0,
                 pi_star: float = PI_STAR):
        # Beta prior mean is the current P(L) estimate.
        self.a = float(a0)
        self.b = float(b0)
        self.pi_star = pi_star

    @property
    def p_live(self) -> float:
        return self.a / (self.a + self.b)

    def update(self, *, p_s_given_live: float, p_s_given_not_live: float) -> float:
        """Bayesian update; returns posterior P(L|S)."""
        pl = self.p_live
        num = p_s_given_live * pl
        den = num + p_s_given_not_live * (1.0 - pl)
        post = num / den if den > 0 else 0.0
        # Fold the posterior back into the Beta counts (evidence accumulation):
        # treat the posterior as a soft observation with unit weight.
        self.a += post
        self.b += (1.0 - post)
        return post

    def state(self, *, sensor_digest: bytes, drand_round: bytes) -> PoLEState:
        p = self.p_live
        digest = H(b"atlas/pole", struct.pack(">d", p), sensor_digest, drand_round)
        return PoLEState(
            p_live=p, state_digest=digest, drand_round=drand_round, operate=p >= self.pi_star
        )


def evaluate_stream(
    samples: Iterable[tuple[float, float]], *, sensor_digest: bytes, drand_round: bytes,
    **prior,
) -> PoLEState:
    """Convenience: run a gate over (p_s_given_live, p_s_given_not_live) pairs."""
    gate = LivenessGate(**prior)
    for psl, psnl in samples:
        gate.update(p_s_given_live=psl, p_s_given_not_live=psnl)
    return gate.state(sensor_digest=sensor_digest, drand_round=drand_round)
