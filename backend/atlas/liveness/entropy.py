"""Entropy operators for liveness assessment (Math Spec v1.4 / GBSS).

The operators the spec names for scoring how *alive* a signal is: Shannon entropy,
Lempel-Ziv complexity, and spectral entropy — plus min-entropy (the conservative,
worst-case cousin we already use as a hard gate). Each takes raw sensor samples and
returns a scalar in a documented range.

LOAD-BEARING INVARIANT: these are MEASUREMENTS of liveness/freshness. Their outputs
only ever TIME and GATE the ratchet (feed the PoLE liveness gate); NONE is ever
folded into a key/value. The value stays clean QRNG. "Entropy times/refreshes; the
key is QRNG." A living body's entropy proves life — it is never the secret.

Pure Python (no numpy): the spectral operator uses a small direct DFT, fine for the
short per-window buffers used here.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Sequence


def shannon_entropy_bits(data: bytes) -> float:
    """Shannon entropy of the BYTE distribution, bits/byte (0..8). 0 for a constant;
    ~8 for uniform bytes. General diversity util."""
    return distribution_entropies(list(data))[0]


def distribution_entropies(symbols: Sequence) -> tuple[float, float]:
    """(Shannon, min-entropy) in bits over a sequence of hashable symbols. Shannon
    = average unpredictability (-Σ p·log2 p); min-entropy = worst-case
    (-log2 max p). Used across snapshots (each snapshot a symbol) so a bit-flipping
    replay loop still reads as few distinct symbols -> low entropy."""
    if not symbols:
        return 0.0, 0.0
    counts = Counter(symbols)
    n = len(symbols)
    shannon = 0.0
    p_max = 0.0
    for c in counts.values():
        p = c / n
        shannon -= p * math.log2(p)
        p_max = max(p_max, p)
    return shannon, -math.log2(p_max)


def lempel_ziv_complexity(data: bytes) -> float:
    """Normalized Lempel-Ziv (LZ76) complexity of the bit sequence, in ~[0,1].

    Counts the distinct patterns the sequence produces (Kaspar-Schuster), then
    normalizes by n/log2(n) — the asymptotic count for a random binary source. So
    genuine noise ~1.0 (incompressible), a repetitive / looped / constant stream ->
    low (compressible). Complements min-entropy for replay/loop detection: a loop
    that flips bits every tick still compresses well -> low LZ.
    """
    bits = "".join(f"{b:08b}" for b in data)
    n = len(bits)
    if n == 0:
        return 0.0
    i = 0
    c = 1           # number of distinct components
    ln = 1          # current prefix length being scanned
    k = 1           # length of the current match
    k_max = 1
    while ln + k <= n:
        if bits[i + k - 1] == bits[ln + k - 1]:
            k += 1
        else:
            k_max = max(k_max, k)
            i += 1
            if i == ln:                 # no match found starting anywhere in prefix
                c += 1
                ln += k_max
                i = 0
                k = 1
                k_max = 1
            else:
                k = 1
    if k != 1:                          # trailing partial component
        c += 1
    # normalize by the random-source asymptote b(n) = n/log2(n)
    norm = n / math.log2(n) if n > 1 else 1.0
    return c / norm


def spectral_entropy(waveform: Sequence[float]) -> float:
    """Normalized spectral entropy of a waveform, in [0,1]. Entropy of the power
    spectral density (DC removed) over its frequency bins, divided by log2(bins).

    Flat spectrum (white noise, a live broadband signal) -> ~1.0; a single dominant
    tone or a constant -> ~0. A live biological waveform (e.g. PPG) sits between —
    structured but not degenerate. Pure-Python direct DFT (O(n^2)); fine for short
    windows.
    """
    n = len(waveform)
    if n < 4:
        return 0.0
    mean = sum(waveform) / n
    x = [v - mean for v in waveform]            # remove DC so a constant -> 0
    half = n // 2
    psd = []
    for kf in range(1, half + 1):
        re = 0.0
        im = 0.0
        w = 2.0 * math.pi * kf / n
        for t in range(n):
            re += x[t] * math.cos(w * t)
            im -= x[t] * math.sin(w * t)
        psd.append(re * re + im * im)
    total = sum(psd)
    if total <= 0.0 or len(psd) < 2:
        return 0.0
    h = 0.0
    for power in psd:
        if power > 0:
            p = power / total
            h -= p * math.log2(p)
    return h / math.log2(len(psd))
