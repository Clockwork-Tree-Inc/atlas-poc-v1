"""Crypto-agility: the credential scheme behind a swappable interface (§3).

BBS is the sole classical primitive. The identity tree calls this INTERFACE
(issue / present / verify / selective-disclose / resolve), never BBS internals,
so a standardized post-quantum anonymous-credential scheme (lattice anon-creds /
PQ group signatures) can be dropped in later with NO change to the tree above the
interface.

Implementations:
  * `BBSCredentialScheme` — the real, vetted BBS+ (Hyperledger Ursa). Default.
  * `MockCredentialScheme` — a non-anonymous stand-in used ONLY to prove the swap
    seam: the tree code is identical across schemes. NOT unlinkable; never ship.

Optional: `ml_dsa_authenticity_*` accompanies a credential with an ML-DSA
signature over the NON-anonymous parts, so credential AUTHENTICITY is
post-quantum even while UNLINKABILITY remains classical (§3). This does NOT make
the anonymity post-quantum — only the authenticity.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Any, List, Optional

from ..crypto.sign import HybridSigKeypair, generate_sig_keypair, sign as hybrid_sign, verify as hybrid_verify
from .levels import AssuranceLevel
from .verification import (
    AtlasVerificationAuthority, InheritedProof, VerificationCredential, VerificationRecord,
)


class CredentialScheme(abc.ABC):
    """The seam. The identity tree depends on THIS, not on BBS."""

    @property
    @abc.abstractmethod
    def verifier_key(self) -> Any: ...

    @abc.abstractmethod
    def issue(self, system_id_handle: bytes, level: AssuranceLevel): ...

    @abc.abstractmethod
    def present(self, credential, *, nonce: bytes, disclose_system_id: bool = False): ...

    @abc.abstractmethod
    def verify(self, verifier_key, proof, *, required: AssuranceLevel) -> bool: ...

    @abc.abstractmethod
    def resolve_system_id(self, proof) -> Optional[bytes]: ...


class BBSCredentialScheme(CredentialScheme):
    """Real BBS+ via Ursa (the production-track scheme)."""

    def __init__(self):
        self._authority = AtlasVerificationAuthority()

    @property
    def verifier_key(self):
        return self._authority.bbs_key

    def issue(self, system_id_handle: bytes, level: AssuranceLevel):
        return self._authority.verify_and_issue(system_id_handle, level)

    def present(self, credential, *, nonce: bytes, disclose_system_id: bool = False):
        return AtlasVerificationAuthority.present(credential, nonce=nonce, disclose_system_id=disclose_system_id)

    def verify(self, verifier_key, proof, *, required: AssuranceLevel) -> bool:
        return AtlasVerificationAuthority.verify_proof(verifier_key, proof, required=required)

    def resolve_system_id(self, proof) -> Optional[bytes]:
        return AtlasVerificationAuthority.resolve_system_id(proof)


# ---------------------------------------------------------------------------
# Mock alternate scheme — ONLY to prove the swap seam (NOT unlinkable).
# ---------------------------------------------------------------------------

@dataclass
class _MockCredential:
    system_id_handle: bytes
    level: AssuranceLevel


@dataclass
class _MockProof:
    level: AssuranceLevel
    system_id_handle: bytes
    nonce: bytes
    signature: bytes
    discloses_system_id: bool


class MockCredentialScheme(CredentialScheme):
    """A stand-in conforming to the same interface, to demonstrate that swapping
    the scheme needs no change in the tree. It is a plain signature (NOT
    unlinkable) — present only proves the seam, never ship it."""

    def __init__(self):
        self._kp = generate_sig_keypair()
        self._verified: set[bytes] = set()

    @property
    def verifier_key(self):
        return self._kp.public

    def issue(self, system_id_handle: bytes, level: AssuranceLevel):
        self._verified.add(system_id_handle)
        return (VerificationRecord(system_id_handle=system_id_handle, level=level),
                _MockCredential(system_id_handle=system_id_handle, level=level))

    def present(self, credential, *, nonce: bytes, disclose_system_id: bool = False):
        sid = credential.system_id_handle if disclose_system_id else b""
        msg = bytes([int(credential.level)]) + nonce + sid
        return _MockProof(level=credential.level, system_id_handle=sid, nonce=nonce,
                          signature=hybrid_sign(self._kp, msg), discloses_system_id=disclose_system_id)

    def verify(self, verifier_key, proof, *, required: AssuranceLevel) -> bool:
        # Real signature check (review: a no-op verify is a footgun — if the mock
        # is ever wired in by mistake, at least it isn't trivially forgeable).
        # NOTE: this scheme is still NOT unlinkable; never ship it.
        msg = bytes([int(proof.level)]) + proof.nonce + proof.system_id_handle
        return hybrid_verify(verifier_key, msg, proof.signature) and proof.level >= required

    def resolve_system_id(self, proof) -> Optional[bytes]:
        return proof.system_id_handle or None if proof.discloses_system_id else None


# ---------------------------------------------------------------------------
# Optional ML-DSA hybrid authenticity over the NON-anonymous parts (§3).
# ---------------------------------------------------------------------------

def ml_dsa_authenticity_sign(kp: HybridSigKeypair, *, level: AssuranceLevel, context: bytes) -> bytes:
    """Post-quantum authenticity over (level, context) — NOT over the anonymity."""
    return hybrid_sign(kp, b"atlas/cred-auth|" + bytes([int(level)]) + b"|" + context)


def ml_dsa_authenticity_verify(pub, *, level: AssuranceLevel, context: bytes, signature: bytes) -> bool:
    return hybrid_verify(pub, b"atlas/cred-auth|" + bytes([int(level)]) + b"|" + context, signature)
