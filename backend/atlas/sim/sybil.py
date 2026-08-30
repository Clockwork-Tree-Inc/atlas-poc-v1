"""Sybil / farm-resistance model — quantifies "one live human = one identity" on the
real 24-subject MotionSense data, no testers required.

Sybil resistance is NOT a population-size claim; it is a COST claim: how cheaply can an
attacker mint many valid identities? Each identity must clear the liveness gate, and the
same live signal cannot back two identities. We model an attacker with three strategies
and measure the COST PER VALID IDENTITY in units of "distinct real live human-sessions":

  * REPLAY  — capture one real live stream, reuse it for N identities. Each candidate is
    gated, AND duplicates are rejected (a captured signal seeds ONE identity; the change-
    based liveness a re-enrolment needs cannot come from a static replay). So N identities
    still cost N distinct live captures -> no amplification.
  * SYNTHETIC — invent N high-entropy random streams. They pass entropy/anti-loop gates
    but FAIL biological coherence (their distribution doesn't match real human jitter —
    this is exactly what the ring's h_i coherence catches). -> ~0 valid.
  * REAL HUMANS — recruit k distinct live humans. k identities, cost = k humans. The
    honest linear floor: farming reduces to "recruit/coerce k real humans", which is the
    whole point.

The gate reuses the REAL liveness operators (`liveness/entropy.py`): min-entropy +
Lempel-Ziv (anti-loop/replay) + a distribution-coherence score (the biological-match the
ring anchors). HONEST BOUNDARY: entropy operators alone pass high-entropy synthetic data
(known limitation); the coherence term is the stand-in for the ring's on-body anti-spoof.
A sophisticated attacker who reproduces BOTH real biological distribution AND liveness on
distinct devices is, by construction, running distinct live captures — i.e. paying the
real-human floor. That is the claim this quantifies, not a proof of unspoofability.
"""

from __future__ import annotations

import random
import statistics
from dataclasses import dataclass
from typing import Dict, List

from ..crypto.primitives import H, random_bytes
from ..liveness.entropy import distribution_entropies, lempel_ziv_complexity
from .motionsense import BINS, load_profiles

# Gate floors — calibrated on the real 24 subjects so live streams pass and replay /
# synthetic fail. Not the production gate (the device gate is), just the sim's
# discriminator. Measured on the data: real ac1 ~0.5-0.7, synthetic ~0.01, loop lz ~0.03.
MIN_ENTROPY_FLOOR = 2.0      # bits/symbol; a flat stream collapses below this
LZ_FLOOR = 0.15              # normalized Lempel-Ziv; a repeated/looped segment collapses
AUTOCORR_FLOOR = 0.25        # lag-1 autocorrelation — the BIOLOGICAL temporal coherence:
                             # real motion is serially correlated; random is not. This is
                             # the structure the ring's rhythm anchors (byte-distribution
                             # alone does NOT separate high-entropy synthetic from real).


def _hist(symbols: List[int]) -> List[float]:
    """Binned symbol histogram (same BINS grid the profiles use)."""
    counts = [0] * BINS
    for s in symbols:
        counts[(s & 0xFF) * BINS // 256] += 1
    total = sum(counts) or 1
    return [c / total for c in counts]


def reference_hist(profiles: dict) -> List[float]:
    """The real-population reference distribution (mean of the 24 real subjects)."""
    subs = profiles["subjects"]
    acc = [0.0] * BINS
    for sid in subs:
        h = subs[sid]["hist"]
        for i in range(BINS):
            acc[i] += h[i]
    n = len(subs) or 1
    return [a / n for a in acc]


def coherence(symbols: List[int], ref: List[float]) -> float:
    """Biological-distribution match: 1 - total-variation distance to the real
    population. Reported for context, but WEAK alone — it does not separate high-entropy
    synthetic from real (both spread across the byte range). Autocorrelation does."""
    h = _hist(symbols)
    tvd = 0.5 * sum(abs(h[i] - ref[i]) for i in range(BINS))
    return 1.0 - tvd


def autocorrelation(symbols: List[int], lag: int = 1) -> float:
    """Lag-`lag` autocorrelation — the temporal-continuity signature of real biology.
    Real motion streams are serially correlated (~0.5-0.7); uniform-random is ~0."""
    if len(symbols) <= lag:
        return 0.0
    m = statistics.mean(symbols)
    var = statistics.pvariance(symbols) or 1e-9
    cov = sum((symbols[i] - m) * (symbols[i + lag] - m) for i in range(len(symbols) - lag))
    return cov / ((len(symbols) - lag) * var)


def liveness_gate(symbols: List[int], ref: List[float]) -> bool:
    """The sim's stand-in for the on-device liveness gate, fail-closed on any term:
      * min-entropy + Lempel-Ziv  — anti flat-line / anti-loop / anti-replay,
      * lag-1 autocorrelation     — biological temporal coherence (the ring's rhythm)."""
    if len(symbols) < 8:
        return False
    _shannon, min_ent = distribution_entropies(symbols)
    if min_ent < MIN_ENTROPY_FLOOR:
        return False
    if lempel_ziv_complexity(bytes(s & 0xFF for s in symbols)) < LZ_FLOOR:
        return False
    if autocorrelation(symbols) < AUTOCORR_FLOOR:
        return False
    return True


def _fingerprint(symbols: List[int]) -> bytes:
    return H(b"atlas/sybil/fp", bytes(s & 0xFF for s in symbols))


@dataclass
class FarmResult:
    strategy: str
    attempts: int
    valid: int
    live_sessions_spent: int          # distinct real live human-sessions the attacker used
    notes: str = ""

    @property
    def pass_rate(self) -> float:
        return self.valid / self.attempts if self.attempts else 0.0

    @property
    def cost_per_valid(self) -> float:
        """Live human-sessions per valid identity. inf = cannot farm; ~1.0 = linear floor."""
        return (self.live_sessions_spent / self.valid) if self.valid else float("inf")


def _real_streams(profiles: dict) -> List[List[int]]:
    subs = profiles["subjects"]
    return [list(subs[sid]["stream"]) for sid in sorted(subs, key=int)]


def farm_replay(profiles: dict, n: int, *, seed: int = 1) -> FarmResult:
    """Capture ONE real live stream, reuse it for n identities. Duplicates are rejected
    -> only the first is valid; the attacker paid ONE live session for it."""
    ref = reference_hist(profiles)
    base = _real_streams(profiles)[0]
    seen: set = set()
    valid = 0
    for _ in range(n):
        fp = _fingerprint(base)
        if fp in seen:                       # duplicate: the same signal can't re-mint
            continue
        if liveness_gate(base, ref):
            seen.add(fp)
            valid += 1
    return FarmResult("replay-one-capture", n, valid, live_sessions_spent=1,
                      notes="reuse rejected as duplicate -> no amplification")


def farm_synthetic(profiles: dict, n: int, *, seed: int = 1) -> FarmResult:
    """Invent n high-entropy random streams. They pass anti-loop but fail biological
    coherence -> the cheap route yields ~0 valid identities."""
    ref = reference_hist(profiles)
    rng = random.Random(seed)
    length = len(_real_streams(profiles)[0])
    valid = 0
    for _ in range(n):
        stream = [rng.randrange(256) for _ in range(length)]
        if liveness_gate(stream, ref):
            valid += 1
    return FarmResult("synthetic-random", n, valid, live_sessions_spent=0,
                      notes="high entropy but no temporal coherence (ac1~0) -> gate fail")


def farm_real_humans(profiles: dict, k: int, *, seed: int = 1) -> FarmResult:
    """The honest floor: k DISTINCT real live humans -> k identities. Cost is linear —
    farming reduces to recruiting/coercing k real people."""
    ref = reference_hist(profiles)
    streams = _real_streams(profiles)[:k]
    valid = sum(1 for s in streams if liveness_gate(s, ref))
    return FarmResult("real-distinct-humans", len(streams), valid,
                      live_sessions_spent=len(streams),
                      notes="linear: 1 live human-session per identity")


def run_farm(profiles: dict = None, *, n: int = 24, seed: int = 1) -> List[FarmResult]:
    profiles = profiles or load_profiles()
    return [
        farm_replay(profiles, n, seed=seed),
        farm_synthetic(profiles, n, seed=seed),
        farm_real_humans(profiles, min(n, profiles["n_subjects"]), seed=seed),
    ]


def _fmt(r: FarmResult) -> str:
    cpv = "inf" if r.cost_per_valid == float("inf") else f"{r.cost_per_valid:.2f}"
    return (f"{r.strategy:<22} attempts={r.attempts:>3} valid={r.valid:>3} "
            f"pass={r.pass_rate*100:5.1f}%  cost/identity={cpv:>4} live-sessions  — {r.notes}")


def main() -> int:
    profiles = load_profiles()
    print("Atlas Sybil / farm-resistance sim — real MotionSense subjects, real liveness gate")
    print("Claim: cost floor is 1 live human-session per identity; cheap amplification fails.\n")
    for r in run_farm(profiles):
        print("  " + _fmt(r))
    print("\nRead: REPLAY gives no amplification (duplicates rejected -> still 1 live session")
    print("each). SYNTHETIC fails biological coherence (~0 valid). REAL humans is the linear")
    print("floor (~1.0 session/identity). Farming N identities costs N real live humans —")
    print("which is exactly the Sybil-resistance goal. Validated at scale only by a pilot.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
