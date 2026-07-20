"""BBS presentations ride INSIDE the PQC tunnel (§1 layer 1, §2).

Every BBS credential presentation is transmitted post-quantum: wrapped to the
authorized verifier with the hybrid ML-KEM-768 + X25519 KEM (the same hybrid as
the rest of the network-facing stack) and AEAD-sealed. The classical BBS proof
NEVER appears on the wire unwrapped.

The load-bearing consequence (§1): the only party that sees a BBS proof in
cleartext is an authorized verifier inside the tunnel. A passive observer or a
harvest-now-decrypt-later collector sees only PQC ciphertext and must break
ML-KEM (post-quantum) FIRST even to reach the classical BBS layer. So the
classical-BBS exposure is bounded to authorized-verifier collusion, not the open
network.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from ..crypto import kem
from ..crypto.primitives import aead_decrypt, aead_encrypt
from .levels import AssuranceLevel
from .verification import InheritedProof


def _serialize(proof: InheritedProof) -> bytes:
    return json.dumps({
        "proof": proof.proof.hex(),
        "revealed": proof.revealed,
        "nonce": proof.nonce.hex(),
        "level": int(proof.level),
        "discloses_system_id": proof.discloses_system_id,
    }).encode()


def _deserialize(blob: bytes) -> InheritedProof:
    d = json.loads(blob.decode())
    return InheritedProof(proof=bytes.fromhex(d["proof"]), revealed=d["revealed"],
                          nonce=bytes.fromhex(d["nonce"]), level=AssuranceLevel(d["level"]),
                          discloses_system_id=d["discloses_system_id"])


@dataclass
class SealedPresentation:
    """What travels on the wire: PQC ciphertext only — no BBS proof in clear."""

    mlkem_ct: bytes
    x25519_eph_pk: bytes
    ciphertext: bytes


def seal_presentation(proof: InheritedProof, recipient: kem.HybridKEMPublic) -> SealedPresentation:
    """Wrap a BBS presentation to an authorized verifier under ML-KEM + X25519."""
    enc = kem.encapsulate(recipient)
    ct = aead_encrypt(enc.shared, _serialize(proof), aad=b"atlas/bbs-presentation")
    return SealedPresentation(mlkem_ct=enc.mlkem_ct, x25519_eph_pk=enc.x25519_eph_pk, ciphertext=ct)


def open_presentation(sealed: SealedPresentation, recipient_kp: kem.HybridKEMKeypair) -> InheritedProof:
    """Authorized verifier (holds the KEM secret) recovers the BBS proof."""
    shared = kem.decapsulate(recipient_kp, sealed.mlkem_ct, sealed.x25519_eph_pk)
    return _deserialize(aead_decrypt(shared, sealed.ciphertext, aad=b"atlas/bbs-presentation"))
