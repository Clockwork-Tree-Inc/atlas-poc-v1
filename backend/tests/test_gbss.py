"""GBSS entropy vector: per-channel densities, honest ring-deferred h_i, and the
richer liveness gate. Densities only gate/time — never a key (invariant)."""

import os
import random

from atlas.liveness.gbss import (
    EntropyVector,
    channel_density,
    gbss_liveness_likelihoods,
    pole_from_gbss,
)


def _noise_wave(n=64):
    random.seed(7)
    return [random.gauss(0, 1) for _ in range(n)]


def test_channel_density_high_for_live_low_for_degenerate():
    live_syms = [os.urandom(8) for _ in range(16)]                 # all-distinct snapshots
    loop_syms = [b"\x01" * 8, b"\x02" * 8] * 8                     # 2-frame loop
    assert channel_density(symbols=live_syms) > 0.6
    assert channel_density(symbols=loop_syms) < 0.4
    assert channel_density(waveform=_noise_wave()) > 0.6           # flat spectrum -> live
    assert channel_density(waveform=[3.0] * 64) == 0.0            # constant -> degenerate
    assert channel_density() == 0.0                               # nothing -> 0


def test_entropy_vector_ring_deferred_and_density_over_present():
    # phone: s_i + c_i present, m_i partial, h_i ring-deferred (None)
    v = EntropyVector(s_i=0.8, c_i=0.7, m_i=0.6)
    assert v.ring_deferred() is True
    assert set(v.present().keys()) == {"s_i", "c_i", "m_i"}       # no h_i on phone
    assert abs(v.density() - (0.8 + 0.7 + 0.6) / 3) < 1e-9
    # when the ring lands, h_i simply raises coverage — same shape
    vr = EntropyVector(s_i=0.8, c_i=0.7, m_i=0.6, h_i=0.9)
    assert vr.ring_deferred() is False and "h_i" in vr.present()


def test_gbss_likelihoods_live_vs_degenerate():
    live = EntropyVector(s_i=0.8, c_i=0.75, m_i=0.7)
    psl, psnl = gbss_liveness_likelihoods(live)
    assert psl > psnl                                             # rich -> live evidence
    dead = EntropyVector(s_i=0.05, c_i=0.03)                      # below the density floor
    psl2, psnl2 = gbss_liveness_likelihoods(dead)
    assert psl2 < 0.1 and psnl2 > 0.9                            # degenerate -> not-live


def test_pole_from_gbss_live_operates_degenerate_fails_closed():
    live = [EntropyVector(s_i=0.8, c_i=0.75, m_i=0.7) for _ in range(30)]
    assert pole_from_gbss(live, drand_round=b"\x00" * 8).operate is True
    dead = [EntropyVector(s_i=0.04, c_i=0.02) for _ in range(30)]
    assert pole_from_gbss(dead, drand_round=b"\x00" * 8).operate is False


def test_density_is_measurement_only_never_a_key():
    """The vector yields a bounded scalar density + probabilities (liveness
    evidence) — there is no path from here to key bytes (invariant)."""
    v = EntropyVector(s_i=0.5, c_i=0.5)
    assert isinstance(v.density(), float) and 0.0 <= v.density() <= 1.0
    psl, psnl = gbss_liveness_likelihoods(v)
    assert isinstance(psl, float) and isinstance(psnl, float)
    assert abs((psl + psnl) - 1.0) < 1e-9
