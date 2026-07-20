"""Entropy operators (Math Spec v1.4): Shannon, min-entropy, Lempel-Ziv
complexity, spectral entropy. Each scores how *alive* a signal is; all are
measurements that only gate/time — never key material."""

import math
import os
import random

from atlas.liveness.entropy import (
    distribution_entropies,
    lempel_ziv_complexity,
    shannon_entropy_bits,
    spectral_entropy,
)


def test_shannon_bounds():
    assert shannon_entropy_bits(b"") == 0.0
    assert shannon_entropy_bits(b"\x00" * 32) == 0.0            # constant -> 0
    assert shannon_entropy_bits(bytes(range(256))) == 8.0       # uniform bytes -> 8


def test_distribution_shannon_and_min_entropy():
    sh, mn = distribution_entropies([b"A", b"B"] * 8)           # two states, half each
    assert abs(sh - 1.0) < 1e-9 and abs(mn - 1.0) < 1e-9
    sh2, mn2 = distribution_entropies([b"A"] * 13 + [b"B", b"C", b"D"])
    assert mn2 < sh2                                            # worst-case < average


def test_lempel_ziv_high_for_random_low_for_repetitive():
    rnd = lempel_ziv_complexity(os.urandom(64))
    constant = lempel_ziv_complexity(b"\x00" * 64)
    loop = lempel_ziv_complexity(b"\x12\x34" * 32)             # 2-byte replay loop
    assert rnd > 0.8                                            # incompressible/live
    assert constant < 0.1 and loop < 0.2                       # compressible/degenerate
    assert rnd > loop > constant


def test_spectral_entropy_flat_high_tone_low():
    random.seed(1)
    noise = [random.gauss(0, 1) for _ in range(64)]
    tone = [math.sin(2 * math.pi * 5 * t / 64) for t in range(64)]
    const = [3.0] * 64
    assert spectral_entropy(noise) > 0.7                        # flat spectrum -> high
    assert spectral_entropy(tone) < 0.2                         # single peak -> low
    assert spectral_entropy(const) == 0.0                       # DC removed -> 0
    assert spectral_entropy([1.0, 2.0]) == 0.0                  # too short -> 0


def test_operators_are_scalar_measurements_not_keys():
    """Sanity that these produce bounded scalar measurements (liveness evidence),
    not byte material — they gate/time, never a value."""
    for v in (lempel_ziv_complexity(os.urandom(32)),
              spectral_entropy([random.gauss(0, 1) for _ in range(32)]),
              shannon_entropy_bits(os.urandom(32))):
        assert isinstance(v, float)
