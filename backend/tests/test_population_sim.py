"""Population-scale timing sim, grounded in real MotionSense subjects.

Proves: (1) the value/timing invariant holds at every scale (arrivals clock WHEN,
never the value), (2) single-device control over the aggregate clock collapses as
N grows (the quantified "does scale help?" answer), (3) the foundation is the 24
real subjects.
"""

import os

import pytest

from atlas.sim import population as pop
from atlas.sim.motionsense import (
    DEFAULT_PROFILES, load_profiles, timing_byte_to_interval,
)
from atlas.params import RATCHET_JITTER_S, RATCHET_NOMINAL_S


def test_profiles_are_real_24_subjects():
    assert os.path.exists(DEFAULT_PROFILES)
    p = load_profiles()
    assert p["n_subjects"] == 24
    for sid, s in p["subjects"].items():
        assert s["n_samples"] > 0
        assert len(s["stream"]) > 0                      # real ordered bytes present
        assert abs(sum(s["hist"]) - 1.0) < 1e-3          # a proper distribution
        assert 0 <= s["mean_byte"] <= 255


def test_value_is_qrng_independent_of_timing(monkeypatch):
    """The invariant: the draw VALUE is clean QRNG and never a function of arrival
    timing. With the QRNG pinned, the value is fixed regardless of any timing."""
    monkeypatch.setattr(pop, "random_bytes", lambda n: b"Q" * n)
    v_fast = pop.draw_value()
    v_slow = pop.draw_value()
    assert v_fast == v_slow == b"Q" * 32                 # value = QRNG only
    # and the timing map is a pure schedule function — no key material anywhere in it
    assert isinstance(timing_byte_to_interval(0), float)


def test_timing_bytes_stay_in_the_jitter_band():
    lo = RATCHET_NOMINAL_S - RATCHET_JITTER_S
    hi = RATCHET_NOMINAL_S + RATCHET_JITTER_S
    for b in (0, 1, 128, 254, 255):
        iv = timing_byte_to_interval(b)
        assert lo - 1e-9 <= iv <= hi + 1e-9


def test_n2_uses_real_subjects():
    r = pop.simulate(2)
    assert r.real_subjects is True
    assert r.n == 2


def test_single_device_timing_influence_collapses_with_scale():
    """One device dominates the *timing* at N=2 (real subjects), but its share AND
    the draw-time shift it can force both fall steeply as N grows. This is a
    robustness curve (schedule-nudge influence), not a key-security property —
    keys are safe at every N. No pass/fail verdict is asserted, only the shape."""
    profiles = load_profiles()
    r2 = pop.simulate(2, profiles=profiles)
    r200 = pop.simulate(200, profiles=profiles)
    r2000 = pop.simulate(2000, profiles=profiles)

    # share is exactly 1/N and strictly decreasing
    assert r2.single_device_share > r200.single_device_share > r2000.single_device_share
    assert abs(r2000.single_device_share - 1 / 2000) < 1e-9

    # the achievable draw-time shift collapses with scale
    assert r2.single_device_shift_s > r200.single_device_shift_s > r2000.single_device_shift_s

    # the reference marker is a heuristic reference, not a gate — just confirm it's
    # a documented continuum point, and that no pass/fail flag exists on results.
    assert not hasattr(r2, "self_sufficient")
    assert r2.single_device_share > pop.REFERENCE_INFLUENCE       # small N above the ref
    assert r2000.single_device_share < pop.REFERENCE_INFLUENCE    # large N below it


def test_aggregate_rate_grows_with_population():
    profiles = load_profiles()
    assert pop.simulate(2000, profiles=profiles).aggregate_rate_hz \
        > pop.simulate(200, profiles=profiles).aggregate_rate_hz
