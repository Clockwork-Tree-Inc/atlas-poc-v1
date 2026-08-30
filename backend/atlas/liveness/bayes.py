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
from ..params import (
    LIVENESS_LIK_CLAMP_EPS,
    LIVENESS_MIN_SAMPLES,
    LIVENESS_PRIOR_A0,
    LIVENESS_PRIOR_B0,
    PI_STAR,
)


@dataclass(frozen=True)
class PoLEState:
    p_live: float
    state_digest: bytes
    epoch_round: bytes
    operate: bool


class LivenessGate:
    """Running Bayesian gate fed per-sample likelihoods.

    Each sample contributes a likelihood ratio via P(S|L) and P(S|¬L). The
    Beta(a0,b0) prior on P(L) is the personal reference accumulated during the
    calibration window (§6). The posterior from one sample becomes the prior for
    the next, so the gate integrates evidence over the stream.

    Threat-model note (M7 "sustained bias"): the PRIMARY control against a
    crafted-likelihood feed is the trust architecture, NOT this belief-math.
      * App Attest gates the software path — the gate runs inside the attested
        app on attested hardware, so an attacker cannot substitute a crafted
        likelihood source without breaking attestation.
      * Usage is fresh-per-eval — the gate is instantiated, fed a bounded batch,
        and discarded per PoLE eval (pole_from_ambient / pole_from_gbss); there
        is NO session-spanning accumulator for a "patient" attacker to drag up.
      * The honest source fail-closes (ambient -> (0.02,0.98) off-body;
        _ring_coherent hard-gates HR/HRV/on-body before Bayes).
    The residual App Attest does NOT cover is a spoofed/replayed physical
    biosignal at the peripheral; that is closed by the SE-signed ring sample
    (ring_SE_sig, Math Spec §D.5 — production ring, not R10), not here.
    The clamp + min-sample-count below are DEFENSE-IN-DEPTH only. Do NOT add a
    decay/window accumulator: it shifts the operating point (rejects genuine
    moderate liveness) to defend a threat already closed above — evaluated and
    rejected 2026-08-13.
    """

    def __init__(self, *, a0: float = LIVENESS_PRIOR_A0, b0: float = LIVENESS_PRIOR_B0,
                 pi_star: float = PI_STAR, min_samples: int = LIVENESS_MIN_SAMPLES,
                 clamp_eps: float = LIVENESS_LIK_CLAMP_EPS):
        # Beta prior mean is the current P(L) estimate.
        self.a = float(a0)
        self.b = float(b0)
        self.pi_star = pi_star
        # M7 hardening: bound single-sample influence + require sustained evidence.
        self.min_samples = int(min_samples)
        self._clamp_eps = float(clamp_eps)
        self._n = 0

    @property
    def p_live(self) -> float:
        return self.a / (self.a + self.b)

    def update(self, *, p_s_given_live: float, p_s_given_not_live: float) -> float:
        """Bayesian update; returns posterior P(L|S).

        M7 hardening: each per-sample likelihood is CLAMPED into [eps, 1-eps] so no
        single crafted sample (e.g. P(S|¬L)->0) can slam the posterior to ~1 in one
        step — the per-sample likelihood ratio is bounded to (1-eps)/eps. The clamp is
        below every legitimate stream's minimum, so it is a no-op for real signals.
        """
        eps = self._clamp_eps
        psl = min(max(p_s_given_live, eps), 1.0 - eps)
        psnl = min(max(p_s_given_not_live, eps), 1.0 - eps)
        pl = self.p_live
        num = psl * pl
        den = num + psnl * (1.0 - pl)
        post = num / den if den > 0 else 0.0
        # Fold the posterior back into the Beta counts (evidence accumulation):
        # treat the posterior as a soft observation with unit weight.
        self.a += post
        self.b += (1.0 - post)
        self._n += 1
        return post

    def state(self, *, sensor_digest: bytes, epoch_round: bytes,
              captured_round: bytes | None = None) -> PoLEState:
        p = self.p_live
        digest = H(b"atlas/pole", struct.pack(">d", p), sensor_digest, epoch_round)
        # FRESHNESS (security review #3): the sample batch must be bound to the CURRENT
        # fresh beacon round. A replayed / pre-canned batch carries a stale (or absent)
        # round and fail-closes here — so a recorded-but-varying feed (still high-entropy),
        # or random bytes, cannot read as live merely by looking un-frozen. captured_round=None
        # keeps legacy callers working (no freshness claim); the ambient/gbss device paths
        # bind it. The UN-FORGEABLE capture-binding (the sensor incorporates the round) is
        # enforced device-side under App Attest; here we enforce the round-match precondition.
        fresh = captured_round is None or captured_round == epoch_round
        # M7 hardening: require sustained evidence — a single (or too-few) sample(s)
        # cannot trip liveness even if p momentarily clears pi*.
        operate = fresh and p >= self.pi_star and self._n >= self.min_samples
        return PoLEState(
            p_live=p, state_digest=digest, epoch_round=epoch_round, operate=operate
        )


def evaluate_stream(
    samples: Iterable[tuple[float, float]], *, sensor_digest: bytes, epoch_round: bytes,
    captured_round: bytes | None = None, **prior,
) -> PoLEState:
    """Convenience: run a gate over (p_s_given_live, p_s_given_not_live) pairs."""
    gate = LivenessGate(**prior)
    for psl, psnl in samples:
        gate.update(p_s_given_live=psl, p_s_given_not_live=psnl)
    return gate.state(sensor_digest=sensor_digest, epoch_round=epoch_round,
                      captured_round=captured_round)
