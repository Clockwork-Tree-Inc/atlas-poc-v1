"""Signatures (§1.3, ATLAS VIII §B.2).

Two distinct roles per the canonical PQC mapping:

  * Routine signatures (beacon, proof tokens, attestations, provenance
    receipts): hybrid ML-DSA-65 + Ed25519. A verifier accepts only if BOTH
    component signatures verify.
  * Long-lived root / TSK and anchors: SPHINCS+ (SLH-DSA). Used standalone for
    the permanent identity root.

FALCON is named for ring secure-element signatures "where present (not on the
R10 — see §0.3)", so it is intentionally absent from the Tier-3 PoC.
"""

from __future__ import annotations

from dataclasses import dataclass

import pyspx.shake_128f as _spx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from dilithium_py.ml_dsa import ML_DSA_65

from .primitives import random_bytes

# ---------------------------------------------------------------------------
# Hybrid ML-DSA-65 + Ed25519 (routine signatures)
# ---------------------------------------------------------------------------


@dataclass
class HybridSigKeypair:
    mldsa_pk: bytes
    mldsa_sk: bytes
    ed_sk: Ed25519PrivateKey
    ed_pk: bytes

    @property
    def public(self) -> "HybridSigPublic":
        return HybridSigPublic(mldsa_pk=self.mldsa_pk, ed_pk=self.ed_pk)


@dataclass(frozen=True)
class HybridSigPublic:
    mldsa_pk: bytes
    ed_pk: bytes

    def encode(self) -> bytes:
        return (
            len(self.mldsa_pk).to_bytes(4, "big")
            + self.mldsa_pk
            + len(self.ed_pk).to_bytes(4, "big")
            + self.ed_pk
        )

    @staticmethod
    def decode(data: bytes) -> "HybridSigPublic":
        """Inverse of encode() — reconstruct a public key from its length-prefixed bytes."""
        off = 0
        n = int.from_bytes(data[off:off + 4], "big"); off += 4
        mldsa_pk = data[off:off + n]; off += n
        m = int.from_bytes(data[off:off + 4], "big"); off += 4
        ed_pk = data[off:off + m]; off += m
        return HybridSigPublic(mldsa_pk=mldsa_pk, ed_pk=ed_pk)


def generate_sig_keypair() -> HybridSigKeypair:
    pk, sk = ML_DSA_65.keygen()
    ed = Ed25519PrivateKey.generate()
    return HybridSigKeypair(
        mldsa_pk=pk, mldsa_sk=sk, ed_sk=ed, ed_pk=ed.public_key().public_bytes_raw()
    )


def keypair_from_seed(seed: bytes) -> HybridSigKeypair:
    """Deterministically derive a child signing keypair from a 32-byte seed.

    Used by the identity tree (§7) so forward-derived children are reproducible
    from System-ID material. ML-DSA keygen here is seeded by passing the seed as
    the RNG source; Ed25519 is derived from the same seed.
    """
    if len(seed) < 32:
        raise ValueError("seed must be >= 32 bytes")
    # ML-DSA-65 deterministic keygen from a 32-byte coin (FIPS 204 KeyGen_internal).
    # Derive independent 32-byte coins for the two components so neither can be
    # recovered from the other.
    mldsa_coin = _derive(seed, b"mldsa")
    ed_coin = _derive(seed, b"ed25519")
    pk, sk = ML_DSA_65._keygen_internal(mldsa_coin)
    ed = Ed25519PrivateKey.from_private_bytes(ed_coin)
    return HybridSigKeypair(
        mldsa_pk=pk, mldsa_sk=sk, ed_sk=ed, ed_pk=ed.public_key().public_bytes_raw()
    )


def _derive(seed: bytes, label: bytes) -> bytes:
    from .primitives import hkdf

    return hkdf(ikm=seed, info=b"atlas/sig-seed/" + label, length=32)


def sign(kp: HybridSigKeypair, message: bytes) -> bytes:
    s_mldsa = ML_DSA_65.sign(kp.mldsa_sk, message)
    s_ed = kp.ed_sk.sign(message)
    return (
        len(s_mldsa).to_bytes(4, "big") + s_mldsa + len(s_ed).to_bytes(4, "big") + s_ed
    )


def verify(pub: HybridSigPublic, message: bytes, signature: bytes) -> bool:
    try:
        off = 0
        n = int.from_bytes(signature[off : off + 4], "big")
        off += 4
        s_mldsa = signature[off : off + n]
        off += n
        m = int.from_bytes(signature[off : off + 4], "big")
        off += 4
        s_ed = signature[off : off + m]
    except Exception:
        return False
    if not ML_DSA_65.verify(pub.mldsa_pk, message, s_mldsa):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(pub.ed_pk).verify(s_ed, message)
    except InvalidSignature:
        return False
    return True


# ---------------------------------------------------------------------------
# SPHINCS+ / SLH-DSA — long-lived root (TSK, §2.1, §7.1)
# ---------------------------------------------------------------------------

SPX_SEED_BYTES = _spx.crypto_sign_SEEDBYTES


@dataclass
class SphincsKeypair:
    pk: bytes
    sk: bytes


def sphincs_keypair_from_seed(seed: bytes) -> SphincsKeypair:
    if len(seed) != SPX_SEED_BYTES:
        raise ValueError(f"SPHINCS+ seed must be {SPX_SEED_BYTES} bytes")
    pk, sk = _spx.generate_keypair(seed)
    return SphincsKeypair(pk=pk, sk=sk)


def sphincs_generate() -> SphincsKeypair:
    return sphincs_keypair_from_seed(random_bytes(SPX_SEED_BYTES))


def sphincs_sign(kp: SphincsKeypair, message: bytes) -> bytes:
    return _spx.sign(message, kp.sk)


def sphincs_verify(pk: bytes, message: bytes, signature: bytes) -> bool:
    return _spx.verify(message, signature, pk)
