"""Shamir 2-of-3 threshold secret sharing over GF(256) (§1.3, §7.3).

Spec role (§1.3): "Threshold -> Shamir 2-of-3 / dsprenkels/sss (audited)".
The audited C library is the production dependency; this is a clean,
byte-wise GF(256) implementation for the offline PoC core. Each byte of the
secret is shared independently with an independent random polynomial, which is
the same construction the audited library uses.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence

from .primitives import random_bytes

# GF(256) with the AES reduction polynomial 0x11B.
_EXP = [0] * 512
_LOG = [0] * 256


def _init_tables() -> None:
    # Fill exp/log tables using generator 0x03 over GF(2^8).
    a = 1
    for i in range(255):
        _EXP[i] = a
        _LOG[a] = i
        a = _gf_mul_notable(a, 0x03)
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _gf_mul_notable(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        b >>= 1
        a = _xtime(a)
    return p & 0xFF


_init_tables()


def _mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("GF(256) division by zero")
    if a == 0:
        return 0
    return _EXP[(_LOG[a] - _LOG[b]) % 255]


@dataclass(frozen=True)
class Share:
    """A single share: x-coordinate (1..255) and the per-byte y values."""

    index: int
    y: bytes

    def encode(self) -> bytes:
        return bytes([self.index]) + self.y

    @staticmethod
    def decode(blob: bytes) -> "Share":
        return Share(index=blob[0], y=blob[1:])


def split(secret: bytes, *, n: int = 3, k: int = 2) -> List[Share]:
    """Split `secret` into `n` shares; any `k` reconstruct it."""
    if not 1 < k <= n < 256:
        raise ValueError("require 1 < k <= n < 256")
    shares_y = [bytearray() for _ in range(n)]
    for byte in secret:
        # random polynomial of degree k-1 with constant term = secret byte
        coeffs = [byte] + list(random_bytes(k - 1))
        for si in range(n):
            x = si + 1  # x-coords 1..n
            acc = 0
            for c in reversed(coeffs):  # Horner
                acc = _mul(acc, x) ^ c
            shares_y[si].append(acc)
    return [Share(index=i + 1, y=bytes(shares_y[i])) for i in range(n)]


def combine(shares: Sequence[Share]) -> bytes:
    """Reconstruct the secret from >= k shares via Lagrange interpolation at 0."""
    if len(shares) < 2:
        raise ValueError("need at least 2 shares")
    length = len(shares[0].y)
    if any(len(s.y) != length for s in shares):
        raise ValueError("shares have inconsistent length")
    xs = [s.index for s in shares]
    if any(x < 1 or x > 255 for x in xs):
        # x=0 is the interpolation point (the secret); a share at x=0, or any
        # index outside the GF(256) field's 1..255 share range, is malformed and
        # silently corrupts reconstruction — reject it rather than return garbage.
        raise ValueError("share index out of range (must be 1..255)")
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate share indices")
    out = bytearray()
    for pos in range(length):
        secret_byte = 0
        for i, si in enumerate(shares):
            xi = si.index
            yi = si.y[pos]
            num, den = 1, 1
            for j, sj in enumerate(shares):
                if i == j:
                    continue
                num = _mul(num, sj.index)         # (0 - x_j) == x_j in GF(2)
                den = _mul(den, xi ^ sj.index)    # (x_i - x_j)
            lagrange = _div(num, den)
            secret_byte ^= _mul(yi, lagrange)
        out.append(secret_byte)
    return bytes(out)
