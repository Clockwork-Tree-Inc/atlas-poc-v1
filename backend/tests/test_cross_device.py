"""Phone <-> ring same-body binding: streams from one live body correlate; a detached or
different-body ring does not. Modeled on real MotionSense streams."""

import random

from atlas.liveness.cross_device import cross_correlation, same_body
from atlas.sim.motionsense import load_profiles

SUBS = load_profiles()["subjects"]
IDS = sorted(SUBS, key=int)


def _noisy(stream, amp, seed):
    rng = random.Random(seed)
    return [v + rng.uniform(-amp, amp) for v in stream]


def test_same_body_streams_correlate():
    body = list(SUBS[IDS[0]]["stream"])
    phone, ring = _noisy(body, 8, 1), _noisy(body, 8, 2)   # same motion, indep sensor noise
    assert cross_correlation(phone, ring) > 0.8
    assert same_body(phone, ring)


def test_detached_idle_ring_fails_closed():
    body = list(SUBS[IDS[0]]["stream"])
    phone = _noisy(body, 8, 1)
    idle_ring = [128.0] * len(body)                          # ring on a table
    assert not same_body(phone, idle_ring)


def test_different_body_ring_fails_closed():
    phone = _noisy(list(SUBS[IDS[0]]["stream"]), 8, 1)
    other_ring = _noisy(list(SUBS[IDS[1]]["stream"]), 8, 2)  # ring on a DIFFERENT person
    assert cross_correlation(phone, other_ring) < 0.4
    assert not same_body(phone, other_ring)


def test_small_timing_offset_is_tolerated():
    body = list(SUBS[IDS[0]]["stream"])
    phone = _noisy(body, 8, 1)
    ring_lagged = ([0.0, 0.0, 0.0] + _noisy(body, 8, 2))[:len(body)]  # ring 3 samples late
    assert same_body(phone, ring_lagged)                    # lag search recovers it


def test_same_body_rejects_short_window_even_when_correlated():
    """3a fix: a short window lets DIFFERENT people clear the floor by chance (measured 21%
    false-accept at 1s). Even a perfectly-correlated short stream must fail CLOSED: below the
    minimum length, same_body refuses to answer."""
    import random as _r
    from atlas.liveness.cross_device import SAME_BODY_MIN_SAMPLES
    rng = _r.Random(1)
    n = SAME_BODY_MIN_SAMPLES - 1
    phone = [rng.gauss(0, 1) for _ in range(n)]
    ring = list(phone)                                  # identical -> correlation ~1.0
    assert cross_correlation(phone, ring) > 0.99        # would clear the floor...
    assert not same_body(phone, ring)                   # ...but too short -> False
