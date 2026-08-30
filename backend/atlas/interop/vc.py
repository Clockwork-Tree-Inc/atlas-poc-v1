"""W3C Verifiable Credential adapter — compact JWS (SD-JWT-style), EdDSA-signed.

Emits an Atlas assertion as a STANDARD compact JWS:
    b64url(header) . b64url(payload) . b64url(EdDSA-sig-over-"header.payload")
Any JOSE verifier accepts this (alg=EdDSA is registered). The PQC-hybrid strength
rides in a custom `atlas` claim (the canonical assertion bytes + the ML-DSA
signature over them) so an Atlas-aware verifier gets full post-quantum assurance.

Issuer = the Atlas key (`did:atlas:<kid>`). Verifiers chain to it, not to any
external trust list — Atlas is its own root.
"""
from __future__ import annotations

from typing import Any, Optional

from ..crypto.sign import HybridSigKeypair, HybridSigPublic
from ._jws import pqc_binding, sign_compact, verify_compact
from .assertion import AtlasAssertion


def to_jws(kp: HybridSigKeypair, assertion: AtlasAssertion) -> str:
    """Serialize the assertion as an EdDSA-signed compact-JWS Verifiable Credential."""
    canonical = assertion.canonical()
    header = {"alg": "EdDSA", "typ": "vc+jwt", "kid": assertion.issuer_kid}
    payload: dict[str, Any] = {
        "iss": "did:atlas:" + assertion.issuer_kid,
        "sub": assertion.subject,
        "iat": int(assertion.issued_at),
        "vc": {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "AtlasVerifiedHuman"],
            "credentialSubject": {
                "id": assertion.subject,
                "claim_type": assertion.claim_type,
                **assertion.claims,
            },
        },
        # epoch/registry + the embedded post-quantum binding (canonical + ML-DSA):
        "atlas": {"epoch": assertion.epoch, "registry": assertion.registry_ptr, **pqc_binding(kp, canonical)},
    }
    return sign_compact(kp, header, payload)


def verify_jws(pub: HybridSigPublic, jws: str, *, require_pqc: bool = True) -> Optional[dict]:
    """Standard EdDSA JWS verification (identical to what any JOSE lib does) plus,
    when require_pqc, the embedded ML-DSA binding. Returns the payload or None."""
    return verify_compact(pub, jws, require_pqc=require_pqc)
