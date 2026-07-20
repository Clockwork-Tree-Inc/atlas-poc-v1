"""MotionSense real-data foundation for the scale sims.

MotionSense: 24 real subjects, iPhone 6s Core Motion (accelerometer + gyroscope),
50 Hz (mmalekzadeh/motion-sense). We turn each subject's real motion trace into a
per-sample "how alive is the carried phone right now" TIMING feature (a byte in
[0,255]) and a jitter profile (histogram + a real ordered sample stream).

INVARIANT: this feature only ever clocks WHEN a draw fires / gates the ratchet
(via `timing_byte_to_interval`). It is NEVER folded into a key/value — the value
stays clean QRNG. `test_population_sim.py` proves keys are independent of it.

The raw dataset is ~73 MB and is NOT committed. This module extracts a small
derived profiles file (`data/motionsense_profiles.json`, 24 subjects) that the
sims load. Regenerate with:
    python -m atlas.sim.motionsense --dataset /path/to/motionsense_root
"""

from __future__ import annotations

import csv
import json
import math
import os
from statistics import mean, pstdev
from typing import Dict, List

from ..params import RATCHET_JITTER_S, RATCHET_NOMINAL_S

BINS = 16
_STREAM_CAP = 1200          # real ordered bytes kept per subject (for N=2 real streams)
_SAMPLE_CAP = 8000          # samples per subject used to build the histogram

_HERE = os.path.dirname(__file__)
DEFAULT_PROFILES = os.path.join(_HERE, "data", "motionsense_profiles.json")


def liveness_byte(ua_x: float, ua_y: float, ua_z: float,
                  rr_x: float, rr_y: float, rr_z: float) -> int:
    """Fuse Core Motion into a live-motion TIMING byte in [0,255]. Mirrors the
    on-device AmbientSensorSource fusion (magnitude of userAcceleration +
    rotationRate). TIMING FEATURE ONLY — never key material."""
    accel = math.sqrt(ua_x * ua_x + ua_y * ua_y + ua_z * ua_z)   # g units
    rot = math.sqrt(rr_x * rr_x + rr_y * rr_y + rr_z * rr_z)      # rad/s
    v = accel * 64.0 + rot * 8.0
    return max(0, min(255, int(v)))


def timing_byte_to_interval(b: int) -> float:
    """Map a timing byte to a ratchet interval in [nominal-jitter, nominal+jitter]
    — identical mapping to RatchetClock. A WHEN, never a value."""
    frac = b / 255.0
    return (RATCHET_NOMINAL_S - RATCHET_JITTER_S) + frac * (2.0 * RATCHET_JITTER_S)


# ---------------------------------------------------------------------------
# Extraction from the raw MotionSense dataset
# ---------------------------------------------------------------------------

def _subject_files(root: str) -> Dict[int, List[str]]:
    dm = os.path.join(root, "A_DeviceMotion_data")
    if not os.path.isdir(dm):
        dm = root  # allow pointing directly at A_DeviceMotion_data
    subjects: Dict[int, List[str]] = {}
    for act in sorted(os.listdir(dm)):
        adir = os.path.join(dm, act)
        if not os.path.isdir(adir):
            continue
        for f in sorted(os.listdir(adir)):
            if f.startswith("sub_") and f.endswith(".csv"):
                sid = int(f[4:-4])
                subjects.setdefault(sid, []).append(os.path.join(adir, f))
    return subjects


def _stream_bytes(files: List[str], cap: int) -> List[int]:
    out: List[int] = []
    for path in files:
        with open(path, newline="") as fh:
            r = csv.reader(fh)
            header = next(r)
            idx = {name: i for i, name in enumerate(header)}
            keys = ["userAcceleration.x", "userAcceleration.y", "userAcceleration.z",
                    "rotationRate.x", "rotationRate.y", "rotationRate.z"]
            cols = [idx[k] for k in keys]
            for row in r:
                if len(row) <= max(cols):
                    continue
                vals = [float(row[c]) for c in cols]
                out.append(liveness_byte(*vals))
                if len(out) >= cap:
                    return out
    return out


def extract_profiles(root: str) -> dict:
    """Build the derived per-subject profiles from the raw dataset."""
    subjects = _subject_files(root)
    if not subjects:
        raise FileNotFoundError(f"no MotionSense subjects under {root!r}")
    out_subjects = {}
    for sid in sorted(subjects):
        stream = _stream_bytes(subjects[sid], cap=_SAMPLE_CAP)
        hist = [0] * BINS
        for b in stream:
            hist[min(BINS - 1, b * BINS // 256)] += 1
        total = sum(hist) or 1
        out_subjects[str(sid)] = {
            "n_samples": len(stream),
            "mean_byte": round(mean(stream), 4) if stream else 0.0,
            "std_byte": round(pstdev(stream), 4) if len(stream) > 1 else 0.0,
            "hist": [round(h / total, 6) for h in hist],
            "stream": stream[:_STREAM_CAP],       # real ordered bytes for N=2
        }
    return {
        "_about": "Derived from MotionSense (mmalekzadeh/motion-sense), 24 real "
                  "iPhone Core Motion subjects. Sensor->TIMING feature only; never key material.",
        "bins": BINS,
        "n_subjects": len(out_subjects),
        "subjects": out_subjects,
    }


def load_profiles(path: str = DEFAULT_PROFILES) -> dict:
    with open(path) as f:
        return json.load(f)


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Extract MotionSense jitter profiles")
    ap.add_argument("--dataset", required=True, help="MotionSense root (contains A_DeviceMotion_data)")
    ap.add_argument("--out", default=DEFAULT_PROFILES)
    args = ap.parse_args()
    prof = extract_profiles(args.dataset)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(prof, f, separators=(",", ":"))
    print(f"wrote {prof['n_subjects']} real-subject profiles -> {args.out}")
    print(f"  ~{os.path.getsize(args.out)//1024} KB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
