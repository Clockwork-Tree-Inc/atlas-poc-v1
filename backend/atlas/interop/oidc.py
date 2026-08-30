"""'Sign in with Atlas' — OIDC ID Token adapter.

An OIDC ID Token is a JWS with standard claims (iss/sub/aud/exp/iat/nonce). Same
EdDSA envelope + embedded ML-DSA binding as the VC adapter. A relying party that
speaks OIDC verifies the EdDSA signature against Atlas's published key (kid),
getting a 'verified live human' login — Atlas acts as the IdP and its own root.
The custom `atlas_verified_human` claim carries the guarantee; `atlas.pqc_mldsa`
carries the post-quantum binding for Atlas-aware verifiers.
"""
from __future__ import annotations

from typing import Any, Optional

from ..crypto.sign import HybridSigKeypair, HybridSigPublic
from ._jws import pqc_binding, sign_compact, verify_compact
from .assertion import CLAIM_LIVE_HUMAN, AtlasAssertion, kid_of


def id_token(
    kp: HybridSigKeypair,
    *,
    subject: str,
    audience: str,
    nonce: str,
    epoch: str,
    issued_at: float,
    expires_at: float,
    extra: Optional[dict[str, Any]] = None,
) -> str:
    """Mint an EdDSA-signed OIDC ID Token asserting a verified live human."""
    kid = kid_of(kp.public)
    # PQC binding over a canonical assertion of the security-relevant fields
    assertion = AtlasAssertion(
        subject=subject,
        claim_type=CLAIM_LIVE_HUMAN,
        claims={"aud": audience, "nonce": nonce, **(extra or {})},
        issued_at=issued_at,
        epoch=epoch,
        issuer_kid=kid,
    )
    canonical = assertion.canonical()
    header = {"alg": "EdDSA", "typ": "JWT", "kid": kid}
    payload: dict[str, Any] = {
        "iss": "did:atlas:" + kid,
        "sub": subject,
        "aud": audience,
        "iat": int(issued_at),
        "exp": int(expires_at),
        "nonce": nonce,
        "atlas_verified_human": True,
        "epoch": epoch,
        "atlas": pqc_binding(kp, canonical),
        **(extra or {}),
    }
    return sign_compact(kp, header, payload)


def verify_id_token(
    pub: HybridSigPublic,
    token: str,
    *,
    audience: Optional[str] = None,
    require_pqc: bool = True,
) -> Optional[dict]:
    """Standard OIDC ID-token verification (EdDSA + iss/aud) plus, when
    require_pqc, the embedded ML-DSA binding. Returns claims or None."""
    payload = verify_compact(pub, token, require_pqc=require_pqc)
    if payload is None:
        return None
    if audience is not None and payload.get("aud") != audience:
        return None
    return payload
