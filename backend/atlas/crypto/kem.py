"""Hybrid KEM — X-Wing-style ML-KEM-768 + X25519 (§1.3, §4.1).

Canonical role (§1.3, ATLAS VIII §B.2): "ML-KEM (Kyber)+X25519 for key
encapsulation ... All PQC runs hybrid (classical+PQC)."

This is an *X-Wing-style* combiner: it follows the X-Wing shape (ML-KEM-768 +
X25519 with the X25519 public key and ciphertext folded into the final KDF) but
is not bit-compatible with the RFC draft — it uses HKDF-SHA256 as the combiner.
PQC is spent only at public-key moments (§4.1); the resulting shared secret is
an AES-256 key used directly or to wrap a content key.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from kyber_py.ml_kem import ML_KEM_768

from .primitives import hkdf_combine
from ..params import LABEL_XWING


@dataclass
class HybridKEMKeypair:
    """A recipient's long-or-ephemeral hybrid public key bundle."""

    mlkem_ek: bytes  # ML-KEM encapsulation (public) key
    mlkem_dk: bytes  # ML-KEM decapsulation (secret) key
    x25519_sk: X25519PrivateKey
    x25519_pk: bytes  # raw 32-byte X25519 public key

    @property
    def public(self) -> "HybridKEMPublic":
        return HybridKEMPublic(mlkem_ek=self.mlkem_ek, x25519_pk=self.x25519_pk)


@dataclass(frozen=True)
class HybridKEMPublic:
    mlkem_ek: bytes
    x25519_pk: bytes


@dataclass(frozen=True)
class Encapsulation:
    """What the sender transmits; `shared` never leaves the sender."""

    mlkem_ct: bytes
    x25519_eph_pk: bytes
    shared: bytes  # 32-byte derived key (sender-side; not transmitted)


def generate_keypair() -> HybridKEMKeypair:
    ek, dk = ML_KEM_768.keygen()
    sk = X25519PrivateKey.generate()
    pk = sk.public_key().public_bytes_raw()
    return HybridKEMKeypair(mlkem_ek=ek, mlkem_dk=dk, x25519_sk=sk, x25519_pk=pk)


def _combine(
    *, ss_mlkem: bytes, ss_x: bytes, mlkem_ct: bytes, x_eph_pk: bytes, recipient_x_pk: bytes
) -> bytes:
    # X-Wing-style: fold both shared secrets PLUS the full transcript — including
    # the ML-KEM ciphertext — so the derived key is bound to this exact exchange
    # (ciphertext transcript-binding, per the security review).
    return hkdf_combine(
        [ss_mlkem, ss_x, mlkem_ct, x_eph_pk, recipient_x_pk],
        info=LABEL_XWING,
        length=32,
    )


def encapsulate(recipient: HybridKEMPublic) -> Encapsulation:
    ss_mlkem, mlkem_ct = ML_KEM_768.encaps(recipient.mlkem_ek)
    eph = X25519PrivateKey.generate()
    eph_pk = eph.public_key().public_bytes_raw()
    ss_x = eph.exchange(X25519PublicKey.from_public_bytes(recipient.x25519_pk))
    shared = _combine(
        ss_mlkem=ss_mlkem,
        ss_x=ss_x,
        mlkem_ct=mlkem_ct,
        x_eph_pk=eph_pk,
        recipient_x_pk=recipient.x25519_pk,
    )
    return Encapsulation(mlkem_ct=mlkem_ct, x25519_eph_pk=eph_pk, shared=shared)


def decapsulate(kp: HybridKEMKeypair, enc_mlkem_ct: bytes, enc_x_eph_pk: bytes) -> bytes:
    ss_mlkem = ML_KEM_768.decaps(kp.mlkem_dk, enc_mlkem_ct)
    ss_x = kp.x25519_sk.exchange(X25519PublicKey.from_public_bytes(enc_x_eph_pk))
    return _combine(
        ss_mlkem=ss_mlkem,
        ss_x=ss_x,
        mlkem_ct=enc_mlkem_ct,
        x_eph_pk=enc_x_eph_pk,
        recipient_x_pk=kp.x25519_pk,
    )
