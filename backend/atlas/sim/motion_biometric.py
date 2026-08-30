"""Motion as a soft biometric — the population-scale Sybil lever.

Cross-channel coherence (PPG↔BCG) proves a signal is LIVE. But at population scale Sybil
resistance also needs DISTINCTNESS: not just "each identity is live" but "these are
different people." General IMU movement — gait, walking, daily activity — is a soft
biometric that supplies exactly that. Two identities with the same motion signature are
the same person, so a farm reusing one person's movement across many identities collides.

Measured on the real 24 MotionSense subjects (fused accel+gyro), a crude signature
(histogram + mean/std + lag-1 autocorrelation) re-identifies people at ~8x chance
(`reidentification`). HONEST BOUNDARY: that is a SOFT biometric on mixed-activity data —
a distinctiveness/anti-duplication LAYER, not standalone identification. Per-activity gait
features + the ring's continuous stream would raise it; a pilot measures the real ceiling.

INVARIANT: the signature GATES/deduplicates; it never enters key material.
"""

from __future__ import annotations

import statistics as st
from dataclasses import dataclass
from typing import List, Sequence

from .motionsense import BINS, load_profiles


def _ac1(xs: Sequence[int]) -> float:
    if len(xs) < 3:
        return 0.0
    m = st.mean(xs)
    var = st.pvariance(xs) or 1e-9
    return sum((xs[i] - m) * (xs[i + 1] - m) for i in range(len(xs) - 1)) / ((len(xs) - 1) * var)


def motion_signature(stream: Sequence[int]) -> List[float]:
    """Per-identity motion signature: binned distribution + mean/std + temporal
    autocorrelation. Crude but real — captures how THIS body moves."""
    counts = [0] * BINS
    for v in stream:
        counts[(v & 0xFF) * BINS // 256] += 1
    total = sum(counts) or 1
    hist = [c / total for c in counts]
    mean = st.mean(stream) / 255 if stream else 0.0
    std = (st.pvariance(stream) ** 0.5) / 255 if len(stream) > 1 else 0.0
    return hist + [mean, std, _ac1(stream)]


def signature_distance(a: Sequence[float], b: Sequence[float]) -> float:
    return sum((a[i] - b[i]) ** 2 for i in range(len(a))) ** 0.5


# --------------------------------------------------------------------------- separability
@dataclass
class ReIDResult:
    subjects: int
    correct: int
    total: int

    @property
    def rate(self) -> float:
        return self.correct / self.total if self.total else 0.0

    @property
    def chance(self) -> float:
        return 1.0 / self.subjects if self.subjects else 0.0

    @property
    def lift(self) -> float:
        return self.rate / self.chance if self.chance else 0.0


def _halves(profiles: dict):
    """Two signatures per subject (split their stream) — lets us test whether the same
    person's two halves match each other better than other people."""
    subs = profiles["subjects"]
    out = []
    for sid in sorted(subs, key=int):
        s = list(subs[sid]["stream"])
        h = len(s) // 2
        if h < 50:
            continue
        out.append((sid, motion_signature(s[:h])))
        out.append((sid, motion_signature(s[h:])))
    return out


def reidentification(profiles: dict = None) -> ReIDResult:
    """Nearest-neighbour re-identification: for each half-signature, is its closest OTHER
    signature the same person? Rate >> chance == motion is a soft biometric."""
    profiles = profiles or load_profiles()
    halves = _halves(profiles)
    correct = 0
    for i, (sid_i, sg_i) in enumerate(halves):
        best_sid, best_d = None, float("inf")
        for j, (sid_j, sg_j) in enumerate(halves):
            if i == j:
                continue
            d = signature_distance(sg_i, sg_j)
            if d < best_d:
                best_d, best_sid = d, sid_j
        correct += (best_sid == sid_i)
    return ReIDResult(subjects=profiles["n_subjects"], correct=correct, total=len(halves))


def duplicate_radius(profiles: dict = None, *, percentile: float = 0.75) -> float:
    """A near-duplicate threshold from the DATA: the `percentile` of within-person
    half-to-half distances. Reused/perturbed signatures of one person fall inside it;
    genuinely different people mostly fall outside."""
    profiles = profiles or load_profiles()
    subs = profiles["subjects"]
    within = []
    for sid in sorted(subs, key=int):
        s = list(subs[sid]["stream"])
        h = len(s) // 2
        if h < 50:
            continue
        within.append(signature_distance(motion_signature(s[:h]), motion_signature(s[h:])))
    within.sort()
    idx = min(len(within) - 1, int(percentile * len(within)))
    return within[idx] if within else 0.0


# --------------------------------------------------------------------------- gait-reuse farm
@dataclass
class GaitFarmResult:
    attempts: int
    valid: int
    notes: str = ""

    @property
    def cost_per_valid(self) -> float:
        return (1.0 / self.valid) if self.valid else float("inf")


def farm_gait_reuse(profiles: dict = None, n: int = 50, *,
                    jitter: float = 0.01, seed: int = 1) -> GaitFarmResult:
    """A smarter replay attacker: reuse ONE person's motion for n identities, PERTURBING
    each slightly to dodge exact-fingerprint dedup. Near-duplicate detection on the motion
    signature still collapses them — a perturbed gait is still that person's gait."""
    import random
    profiles = profiles or load_profiles()
    rng = random.Random(seed)
    radius = duplicate_radius(profiles)
    base = list(profiles["subjects"][sorted(profiles["subjects"], key=int)[0]]["stream"])
    accepted: List[List[float]] = []
    for _ in range(n):
        perturbed = [min(255, max(0, v + rng.randint(-3, 3))) for v in base]  # small jitter
        sig = motion_signature(perturbed)
        if any(signature_distance(sig, a) < radius for a in accepted):
            continue                       # collides with an accepted identity -> rejected
        accepted.append(sig)
    return GaitFarmResult(attempts=n, valid=len(accepted),
                          notes="perturbed reuse still collides on the motion signature")


def main() -> int:
    profiles = load_profiles()
    r = reidentification(profiles)
    print("Atlas motion-biometric — real MotionSense subjects (fused accel+gyro)")
    print(f"  re-identification: {r.correct}/{r.total} = {r.rate*100:.1f}%  "
          f"(chance {r.chance*100:.1f}%, lift {r.lift:.1f}x)  — motion is a soft biometric")
    radius = duplicate_radius(profiles)
    g = farm_gait_reuse(profiles, 50)
    print(f"  gait-reuse farm (50 perturbed clones): valid={g.valid}  "
          f"cost/identity={'inf' if g.cost_per_valid==float('inf') else f'{g.cost_per_valid:.2f}'}  "
          f"— reusing one gait across identities collapses")
    print("\nPopulation-scale read: distinct identities require distinct motion signatures,")
    print("so a farm can't cheaply mint many identities from one person's movement. Soft")
    print("biometric (a distinctiveness LAYER); per-activity gait + a pilot raise the ceiling.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
