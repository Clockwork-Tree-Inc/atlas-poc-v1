"""A real, sound, non-interactive ZK proof of liveness (TRUST_LAYER.md #14).

STATEMENT (what the verifier learns): "the prover holds a liveness score `w` committed in a
Pedersen commitment `C`, and `w ≥ τ`" — and NOTHING else about `w` (not its value, not the raw
physiology behind it). This is the provisional's `zk_prove(safe, thresholds, liveness, commit)`.

CONSTRUCTION — a bounded ZK range proof from standard Sigma protocols, made non-interactive with
Fiat–Shamir:
  * Pedersen commitment `Ped(v, r) = g^v · h^r` over the prime-order (order-q) subgroup of a
    2048-bit MODP safe-prime group. `g = 4` (a QR, order q); `h` is a nothing-up-my-sleeve
    hash-to-group element, so `log_g h` is unknown (⇒ the commitment is computationally binding
    and perfectly hiding).
  * Write `v = w − τ = Σ_i b_i 2^i` (n bits). Commit each bit `C_i = Ped(b_i, r_i)` and prove
    `b_i ∈ {0,1}` with a Chaum–Pedersen OR-proof ("C_i opens to 0" OR "C_i opens to 1"), the
    false branch SIMULATED (that is the zero-knowledge). The verifier recomputes
    `C_w = g^τ · Π C_i^{2^i}` = Ped(w, Σ r_i 2^i); the bit-proofs force `w ∈ [τ, τ + 2^n − 1]`,
    hence `w ≥ τ`.

SECURITY (honest boundaries):
  * SOUND under discrete-log in the group (special soundness of each Sigma protocol) — a prover
    who does NOT know a bit opening, or whose `w < τ`, cannot make a verifying proof except with
    negligible probability. Completeness is bounded: `w` must lie in `[τ, τ + 2^n)` to be provable.
  * ZERO-KNOWLEDGE in the random-oracle model (Fiat–Shamir): the proof reveals only the range.
  * This is a genuine NIZK, NOT a SNARK — no trusted setup, no circuit compiler. A production
    build uses a curve-based system (Bulletproofs / a STARK) for compactness. Because it is
    2048-bit modexp it is a Python-only reference (like `recovery/oprf.py`); the security argument
    and the STATEMENT carry over to the production proof system.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from ..crypto.primitives import H
from ..recovery.oprf import _P as P
from ..recovery.oprf import _Q as Q
from ..recovery.oprf import _i2osp, _in_subgroup, _random_scalar, hash_to_group

# Generators of the order-q subgroup. g = 2^2 (a QR ⇒ order q). h is a hash-to-group element with
# unknown discrete log to base g (nothing-up-my-sleeve), so Pedersen binding holds.
G = pow(2, 2, P)
Hh = hash_to_group(b"atlas/zk/pedersen-h")
_GINV = pow(G, -1, P)


class ZKError(Exception):
    pass


def _fs_scalar(*chunks: bytes) -> int:
    """Fiat–Shamir challenge in [0, Q)."""
    return int.from_bytes(H(b"atlas/zk/fs", *chunks), "big") % Q


def pedersen(v: int, r: int) -> int:
    """Ped(v, r) = g^v · h^r mod P (perfectly hiding, computationally binding)."""
    return (pow(G, v % Q, P) * pow(Hh, r % Q, P)) % P


# --------------------------------------------------------------------------- bit OR-proof
@dataclass(frozen=True)
class BitProof:
    """A Chaum–Pedersen OR-proof that a commitment opens to 0 OR 1 (the real branch honest, the
    other simulated). `e0 + e1 = FS(challenge)` binds them together."""

    t0: int
    t1: int
    e0: int
    e1: int
    z0: int
    z1: int


def _prove_bit(commitment: int, bit: int, r: int, ctx: bytes) -> BitProof:
    # Y0 = C (statement "C = h^r0"); Y1 = C·g^-1 (statement "C·g^-1 = h^r1").
    y0 = commitment
    y1 = (commitment * _GINV) % P
    if bit == 0:
        k = _random_scalar()
        t0 = pow(Hh, k, P)
        e1 = _random_scalar()
        z1 = _random_scalar()
        t1 = (pow(Hh, z1, P) * pow(y1, (-e1) % Q, P)) % P          # simulate branch 1
        e = _fs_scalar(ctx, _i2osp(commitment), _i2osp(t0), _i2osp(t1))
        e0 = (e - e1) % Q
        z0 = (k + e0 * r) % Q
    elif bit == 1:
        k = _random_scalar()
        t1 = pow(Hh, k, P)
        e0 = _random_scalar()
        z0 = _random_scalar()
        t0 = (pow(Hh, z0, P) * pow(y0, (-e0) % Q, P)) % P          # simulate branch 0
        e = _fs_scalar(ctx, _i2osp(commitment), _i2osp(t0), _i2osp(t1))
        e1 = (e - e0) % Q
        z1 = (k + e1 * r) % Q
    else:
        raise ZKError("bit must be 0 or 1")
    return BitProof(t0=t0, t1=t1, e0=e0, e1=e1, z0=z0, z1=z1)


def _verify_bit(commitment: int, pf: BitProof, ctx: bytes) -> bool:
    # every RECEIVED group element must be in the prime-order subgroup, else a malicious prover
    # could smuggle a small-subgroup component past the Sigma checks.
    if not (_in_subgroup(commitment) and _in_subgroup(pf.t0) and _in_subgroup(pf.t1)):
        return False
    y0 = commitment
    y1 = (commitment * _GINV) % P
    e = _fs_scalar(ctx, _i2osp(commitment), _i2osp(pf.t0), _i2osp(pf.t1))
    if (pf.e0 + pf.e1) % Q != e:
        return False
    ok0 = pow(Hh, pf.z0, P) == (pf.t0 * pow(y0, pf.e0, P)) % P
    ok1 = pow(Hh, pf.z1, P) == (pf.t1 * pow(y1, pf.e1, P)) % P
    return ok0 and ok1


# --------------------------------------------------------------------------- liveness range proof
@dataclass(frozen=True)
class LivenessProof:
    """Proof that the committed liveness score `w` satisfies `w ≥ threshold` (and `w < threshold +
    2^bits`), revealing nothing else. `commitment` is `Ped(w, ·)`, recomputed and checked by the
    verifier from the per-bit commitments."""

    threshold: int
    bits: int
    context: bytes
    commitment: int
    bit_commitments: List[int]
    bit_proofs: List[BitProof]


def prove_liveness(score: int, threshold: int, *, bits: int = 32,
                   context: bytes = b"") -> LivenessProof:
    """Prove `score ≥ threshold` in zero knowledge. `score` and `threshold` are non-negative
    integers (e.g. a quantised liveness margin); `bits` bounds the provable range: the prover must
    have `threshold ≤ score < threshold + 2^bits`."""
    if score < 0 or threshold < 0:
        raise ZKError("score and threshold must be non-negative")
    v = score - threshold
    if not 0 <= v < (1 << bits):
        raise ZKError(f"score not in provable range [threshold, threshold+2^{bits})")

    bit_commitments: List[int] = []
    bit_proofs: List[BitProof] = []
    r_list: List[int] = []
    for i in range(bits):
        b_i = (v >> i) & 1
        r_i = _random_scalar()
        c_i = pedersen(b_i, r_i)
        bit_commitments.append(c_i)
        r_list.append(r_i)
        bit_proofs.append(_prove_bit(c_i, b_i, r_i, context + i.to_bytes(4, "big")))

    commitment = (pow(G, threshold % Q, P) * _combine_bits(bit_commitments)) % P
    return LivenessProof(threshold=threshold, bits=bits, context=context,
                         commitment=commitment, bit_commitments=bit_commitments,
                         bit_proofs=bit_proofs)


def verify_liveness(pf: LivenessProof) -> bool:
    """Verify a liveness proof. Returns True iff every bit is proven ∈ {0,1} and the committed
    value reconstructs the claimed `commitment` — i.e. the hidden score is ≥ threshold."""
    if len(pf.bit_commitments) != pf.bits or len(pf.bit_proofs) != pf.bits:
        return False
    # the commitment must be exactly g^threshold · Π C_i^{2^i} (binds the score to the bits)
    expected = (pow(G, pf.threshold % Q, P) * _combine_bits(pf.bit_commitments)) % P
    if expected != pf.commitment:
        return False
    for i, (c_i, bp) in enumerate(zip(pf.bit_commitments, pf.bit_proofs)):
        if not _in_subgroup(c_i):
            return False
        if not _verify_bit(c_i, bp, pf.context + i.to_bytes(4, "big")):
            return False
    return True


def _combine_bits(bit_commitments: List[int]) -> int:
    """Π C_i^{2^i} mod P = Ped(Σ b_i 2^i, Σ r_i 2^i)."""
    acc = 1
    for i, c_i in enumerate(bit_commitments):
        acc = (acc * pow(c_i, 1 << i, P)) % P
    return acc
