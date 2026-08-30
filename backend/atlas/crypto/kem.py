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

from .primitives import hkdf, hkdf_combine
from ..params import LABEL_XWING

# ---------------------------------------------------------------------------
# ML-KEM backend safety (security review #7): the pure-Python kyber-py reference
# is NOT constant-time. On a PUBLICLY-REACHABLE node doing decapsulation, where an
# attacker can measure response times, that is a real timing side channel (far more
# practical than a quantum attack).
#
# BACKEND SELECTION: when liboqs (the audited constant-time C implementation) is
# installed — `pip install liboqs-python`, which deploy/install-node.sh builds and
# then asserts via require_constant_time_kem() before the node is allowed to start —
# encapsulation/decapsulation run through it and KEM_CONSTANT_TIME is True. Both
# backends implement final FIPS 203 ML-KEM-768, so keys/ciphertexts interoperate
# (cross-verified by tests/test_kem_liboqs.py). Without liboqs (dev/Mac/tests) the
# reference runs and the fail-closed guard below refuses public exposure.
# Seeded keygen (keypair_from_seed) stays on the reference derandomised path —
# keygen is local and not attacker-timeable; only encaps/decaps face the network.
# ---------------------------------------------------------------------------
try:  # constant-time native backend (hosted nodes)
    import oqs as _oqs

    _OQS_ALG = "ML-KEM-768"
    KEM_BACKEND = "liboqs"
    KEM_CONSTANT_TIME = True
except ImportError:  # dev / LAN / tests — reference only
    _oqs = None
    KEM_BACKEND = "reference-kyber-py"
    KEM_CONSTANT_TIME = False


def _mlkem_keygen() -> tuple[bytes, bytes]:
    if _oqs is not None:
        k = _oqs.KeyEncapsulation(_OQS_ALG)
        ek = k.generate_keypair()
        return ek, k.export_secret_key()
    return ML_KEM_768.keygen()


def _mlkem_encaps(ek: bytes) -> tuple[bytes, bytes]:
    """-> (shared_secret, ciphertext), normalized across backends."""
    if _oqs is not None:
        ct, ss = _oqs.KeyEncapsulation(_OQS_ALG).encap_secret(ek)
        return ss, ct
    return ML_KEM_768.encaps(ek)


def _mlkem_decaps(dk: bytes, ct: bytes) -> bytes:
    if _oqs is not None:
        return _oqs.KeyEncapsulation(_OQS_ALG, secret_key=dk).decap_secret(ct)
    return ML_KEM_768.decaps(dk, ct)


class InsecureKEMBackend(RuntimeError):
    """A publicly-reachable node would decapsulate with a non-constant-time ML-KEM
    backend — a timing side channel. Install + wire a constant-time impl (liboqs /
    PQClean) before exposing decapsulation to the network."""


def require_constant_time_kem() -> None:
    """Fail-closed guard. Call at startup on ANY publicly-reachable node that
    decapsulates (see net/node_server.py, tunnel_backend.py). Raises if the active
    ML-KEM backend is not constant-time, so the timing-leaky reference impl can never
    be deployed where an attacker can measure decapsulation time. Dev/LAN nodes
    (no remote timing oracle) do not call this."""
    if not KEM_CONSTANT_TIME:
        raise InsecureKEMBackend(
            f"ML-KEM backend '{KEM_BACKEND}' is not constant-time; a publicly-reachable "
            "node must install + wire a constant-time impl (liboqs or PQClean/pqcrypto). "
            "The reference kyber-py is dev/LAN/test-only.")


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
    ek, dk = _mlkem_keygen()
    sk = X25519PrivateKey.generate()
    pk = sk.public_key().public_bytes_raw()
    return HybridKEMKeypair(mlkem_ek=ek, mlkem_dk=dk, x25519_sk=sk, x25519_pk=pk)


def keypair_from_seed(seed: bytes) -> HybridKEMKeypair:
    """DETERMINISTIC hybrid KEM keypair from a seed — for TreeKEM node keys derived from path
    secrets. ML-KEM via FIPS-203 derandomised keygen (d, z derived from the seed) + X25519 from a
    seed-derived scalar. The same seed yields the same keypair, so a member who learns a path
    secret can recompute the node keypair. Still PQ-hybrid (ML-KEM-768 + X25519)."""
    d = hkdf(ikm=seed, info=b"atlas/kem/mlkem-d", length=32)
    z = hkdf(ikm=seed, info=b"atlas/kem/mlkem-z", length=32)
    ek, dk = ML_KEM_768._keygen_internal(d, z)
    sk = X25519PrivateKey.from_private_bytes(hkdf(ikm=seed, info=b"atlas/kem/x25519", length=32))
    return HybridKEMKeypair(mlkem_ek=ek, mlkem_dk=dk, x25519_sk=sk,
                            x25519_pk=sk.public_key().public_bytes_raw())


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
    ss_mlkem, mlkem_ct = _mlkem_encaps(recipient.mlkem_ek)
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
    ss_mlkem = _mlkem_decaps(kp.mlkem_dk, enc_mlkem_ct)
    ss_x = kp.x25519_sk.exchange(X25519PublicKey.from_public_bytes(enc_x_eph_pk))
    return _combine(
        ss_mlkem=ss_mlkem,
        ss_x=ss_x,
        mlkem_ct=enc_mlkem_ct,
        x_eph_pk=enc_x_eph_pk,
        recipient_x_pk=kp.x25519_pk,
    )
