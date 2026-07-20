"""Population-scale timing simulation, grounded in real MotionSense subjects.

Ladder: N=2 uses two REAL subjects' ordered streams directly; N=2,000 / 20,000 are
SYNTHESIZED by resampling+perturbing the 24 real subjects' jitter histograms
(real-derived variation, not invented). Each device emits presence ARRIVALS timed
by its live signal; the aggregate arrival stream clocks the LK/epoch QRNG firing.

INVARIANT: arrivals clock WHEN a draw fires; the draw VALUE is clean QRNG,
independent of all arrival timing (see `draw_value` + test_population_sim).

Metrics per scale:
  * aggregate_rate_hz      — arrivals/sec feeding the clock (grows with N).
  * inter_draw_cv          — cadence variability; at scale it CONVERGES to the
                             superposition limit (~1/sqrt(draw_every)), i.e. a
                             stable, well-characterized cadence (not a shrinking
                             one — small-N traces are artificially regular).
  * single_device_timing_influence — share of arrivals one device contributes
                             (=1/N) and the measured draw-time shift one device can
                             force (→ 0 with N): the "does scale help?" curve.

IMPORTANT — what this metric is (and isn't): it measures influence over TIMING
(when draws fire), NOT over key material. Timing never enters the value (clean
QRNG), so the keys are safe at EVERY N — even N=2 with 50% timing influence. So
this is a robustness/quality curve (how much any one party can nudge the
schedule), not a vulnerability. There is deliberately NO pass/fail verdict: a
`REFERENCE_INFLUENCE` marker is provided only as an explicit heuristic reference
point, not a security gate.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from statistics import mean, pstdev
from typing import Callable, Dict, List, Tuple

from ..crypto.primitives import random_bytes
from .motionsense import BINS, load_profiles, timing_byte_to_interval

WINDOW_S = 600.0
DRAW_EVERY = 8          # LK fires every Nth aggregate presence arrival

# A HEURISTIC REFERENCE POINT ONLY — not a security gate, not a pass/fail line.
# Keys are safe at every N (timing never enters the value); this just marks a
# nice-to-reach level of single-device timing influence for full-scale robustness.
REFERENCE_INFLUENCE = 0.01     # 1% single-device timing influence (reference marker)


def draw_value() -> bytes:
    """The value fired at a draw: clean QRNG. Arrival TIMING never enters it."""
    return random_bytes(32)


# ---------------------------------------------------------------------------
# Build a population from the real profiles
# ---------------------------------------------------------------------------

def _sample_byte_from_hist(hist: List[float], rng: random.Random) -> int:
    r = rng.random()
    cum = 0.0
    for b in range(BINS):
        cum += hist[b]
        if r <= cum:
            lo = b * 256 // BINS
            hi = (b + 1) * 256 // BINS
            return rng.randrange(lo, max(lo + 1, hi))
    return rng.randrange(0, 256)


def _perturb(hist: List[float], rng: random.Random) -> List[float]:
    """Real-derived variation: jitter each bin of a real subject's histogram."""
    out = [max(0.0, h + rng.uniform(-0.02, 0.02)) for h in hist]
    s = sum(out) or 1.0
    return [h / s for h in out]


def _byte_source(profiles: dict, n: int, rng: random.Random) -> List[Callable[[], int]]:
    """One byte-generator per device. Real subjects for small N; perturbed
    resamples of the 24 real profiles for large N."""
    subjects = profiles["subjects"]
    ids = sorted(subjects, key=int)
    sources: List[Callable[[], int]] = []
    if n <= len(ids):
        for sid in ids[:n]:                          # REAL ordered streams
            stream = subjects[sid]["stream"]
            it = iter(stream)
            def gen(_stream=stream, _box=[iter(stream)]):
                try:
                    return next(_box[0])
                except StopIteration:
                    _box[0] = iter(_stream)
                    return next(_box[0])
            sources.append(gen)
    else:
        for _ in range(n):                           # SYNTH from a real base
            base = subjects[ids[rng.randrange(len(ids))]]
            hist = _perturb(base["hist"], rng)
            r = random.Random(rng.random())
            sources.append(lambda _h=hist, _r=r: _sample_byte_from_hist(_h, _r))
    return sources


def _arrivals(byte_gen: Callable[[], int], window_s: float, rng: random.Random) -> List[float]:
    t = rng.uniform(0.0, 10.0)                       # random join phase (decorrelation)
    out: List[float] = []
    while t < window_s:
        t += timing_byte_to_interval(byte_gen())
        if t < window_s:
            out.append(t)
    return out


@dataclass
class ScaleResult:
    n: int
    real_subjects: bool
    aggregate_rate_hz: float
    inter_draw_cv: float
    single_device_share: float
    single_device_shift_s: float
    n_draws: int


def simulate(n: int, *, profiles: dict = None, window_s: float = WINDOW_S,
             draw_every: int = DRAW_EVERY, seed: int = 1) -> ScaleResult:
    profiles = profiles or load_profiles()
    rng = random.Random(seed)
    sources = _byte_source(profiles, n, rng)
    per_device = [_arrivals(g, window_s, rng) for g in sources]

    tagged: List[Tuple[float, int]] = [(t, i) for i, arr in enumerate(per_device) for t in arr]
    tagged.sort()
    times = [t for t, _ in tagged]

    draw_pos = list(range(draw_every - 1, len(times), draw_every))
    draw_times = [times[j] for j in draw_pos]
    inter = [b - a for a, b in zip(draw_times, draw_times[1:])]
    cv = (pstdev(inter) / mean(inter)) if len(inter) > 1 and mean(inter) > 0 else 0.0

    # adversary = device 0; recompute the clock with its arrivals removed and
    # measure how far it can shift the draw schedule (its control over "when").
    honest = [t for (t, i) in tagged if i != 0]
    honest_draws = [honest[j] for j in range(draw_every - 1, len(honest), draw_every)]
    m = min(len(draw_times), len(honest_draws))
    shift = mean(abs(draw_times[i] - honest_draws[i]) for i in range(m)) if m else 0.0

    share = 1.0 / n
    return ScaleResult(
        n=n, real_subjects=(n <= profiles["n_subjects"]),
        aggregate_rate_hz=round(len(times) / window_s, 4),
        inter_draw_cv=round(cv, 4),
        single_device_share=round(share, 6),
        single_device_shift_s=round(shift, 4),
        n_draws=len(draw_times),
    )


def run_ladder(scales=(2, 8, 24, 2000, 20000), *, seed: int = 1) -> List[ScaleResult]:
    profiles = load_profiles()
    return [simulate(n, profiles=profiles, seed=seed) for n in scales]


def _fmt(r: ScaleResult) -> str:
    tag = "REAL subjects" if r.real_subjects else "synth (real-derived)"
    ref = "  ≤ref" if r.single_device_share <= REFERENCE_INFLUENCE else ""
    return (f"N={r.n:>6}  [{tag:<20}]  rate={r.aggregate_rate_hz:>8.3f}/s  "
            f"draws={r.n_draws:>5}  cadence_CV={r.inter_draw_cv:.3f}  "
            f"1-device timing-influence: share={r.single_device_share*100:7.4f}% "
            f"shift={r.single_device_shift_s:6.3f}s{ref}")


def main() -> int:
    print("Atlas population timing sim — grounded in MotionSense (24 real iPhone subjects)")
    print("Invariant: arrivals clock WHEN draws fire; values are clean QRNG (independent).")
    print(f"Reference marker (heuristic, NOT a gate): single-device timing influence "
          f"≤ {REFERENCE_INFLUENCE*100:.0f}%\n")
    for r in run_ladder():
        print("  " + _fmt(r))
    print("\nRead: KEYS ARE SAFE AT EVERY N — timing never enters the value, so this is a")
    print("robustness curve (how much one party can nudge the *schedule*), not a")
    print("vulnerability. N<=24 is ALL REAL and shows single-device timing-influence")
    print("collapsing ~1/N (50% @ N=2 → ~4% @ N=24). A handful of devices already")
    print("demonstrates it; driving influence below the ~1% reference is a full-scale")
    print("aspiration, not a requirement. drand sits underneath as the floor throughout.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
