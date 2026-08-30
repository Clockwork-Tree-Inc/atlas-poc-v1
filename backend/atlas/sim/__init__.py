"""Population-scale simulation grounded in real iPhone sensor data (MotionSense).

Real foundation → synthesized crowd. The 24 real MotionSense subjects give the
genuine per-person timing/jitter characteristics; the 2,000 / 20,000 populations
are synthesized by resampling/perturbing those 24 real profiles (real-derived
variation, not invented jitter).

LOAD-BEARING INVARIANT (enforced + tested): the sensor signal is turned into a
TIMING/GATING feature only — it clocks WHEN the QRNG draws fire and gates the
ratchet; it NEVER becomes key material. Keys stay clean QRNG at every scale.
"""

from .motionsense import (
    extract_profiles, liveness_byte, timing_byte_to_interval, load_profiles,
)

__all__ = ["extract_profiles", "liveness_byte", "timing_byte_to_interval", "load_profiles"]
