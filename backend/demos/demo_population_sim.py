"""ATLAS PoC — population-scale timing sim grounded in real iPhone data.

Runs the ladder: N=2 (two REAL MotionSense subjects) / 2,000 / 20,000 (synthesized
by perturbing the 24 real jitter profiles). Shows single-device control over the
aggregate LK clock collapsing as N grows, while the value stays clean QRNG.

Run:  python demos/demo_population_sim.py
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from atlas.sim.population import main

if __name__ == "__main__":
    raise SystemExit(main())
