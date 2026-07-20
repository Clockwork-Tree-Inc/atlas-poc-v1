"""Sybil / farm-resistance sim: the cost floor is one live human-session per identity,
cheap amplification (replay, synthetic) yields no gain — measured on the real 24 subjects.
"""

import random

from atlas.sim.motionsense import load_profiles
from atlas.sim.sybil import (
    autocorrelation,
    farm_real_humans,
    farm_replay,
    farm_synthetic,
    liveness_gate,
    reference_hist,
)

PROFILES = load_profiles()
REF = reference_hist(PROFILES)


def _real(i):
    subs = PROFILES["subjects"]
    return list(subs[sorted(subs, key=int)[i]]["stream"])


# --------------------------------------------------------------------------- the gate
def test_real_live_stream_passes_the_gate():
    assert liveness_gate(_real(0), REF)


def test_looped_replay_is_rejected_by_anti_loop():
    base = _real(0)
    loop = (base[:20] * (len(base) // 20 + 1))[:len(base)]   # short segment repeated
    assert not liveness_gate(loop, REF)


def test_synthetic_random_lacks_temporal_coherence():
    rng = random.Random(1)
    synth = [rng.randrange(256) for _ in range(len(_real(0)))]
    assert autocorrelation(synth) < 0.25 < autocorrelation(_real(0))
    assert not liveness_gate(synth, REF)


# --------------------------------------------------------------------------- farm economics
def test_replay_gives_no_amplification():
    # Reusing one capture for many identities yields exactly ONE valid identity for ONE
    # live session — no matter how many attempts. cost/identity stays 1.0, never < 1.
    r = farm_replay(PROFILES, 100)
    assert r.valid == 1 and r.live_sessions_spent == 1
    assert r.cost_per_valid == 1.0


def test_synthetic_farm_yields_nothing():
    r = farm_synthetic(PROFILES, 100)
    assert r.valid == 0
    assert r.cost_per_valid == float("inf")     # cannot farm the cheap way


def test_real_humans_is_the_linear_floor():
    k = PROFILES["n_subjects"]
    r = farm_real_humans(PROFILES, k)
    assert r.valid == k                         # every distinct live human -> one identity
    assert abs(r.cost_per_valid - 1.0) < 1e-9   # exactly one live session per identity


def test_no_strategy_beats_one_live_human_per_identity():
    # The Sybil claim in one assertion: no strategy produces an identity for less than
    # one distinct live human-session.
    for r in (farm_replay(PROFILES, 50), farm_synthetic(PROFILES, 50),
              farm_real_humans(PROFILES, PROFILES["n_subjects"])):
        assert r.cost_per_valid >= 1.0
