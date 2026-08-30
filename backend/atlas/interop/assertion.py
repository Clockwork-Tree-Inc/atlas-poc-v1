"""Canonical Atlas Verifiable Assertion — the interop hub.

One signed claim that every standard adapter (VC, C2PA, WebAuthn/OIDC) wraps.
Dual signature by design:

  * Ed25519 (JOSE 'EdDSA', a REGISTERED algorithm) over the canonical bytes —
    so any stock external verifier can check it. This is what makes it interop.
  * ML-DSA-65 over the same bytes — the embedded post-quantum binding, for
    Atlas-native verifiers. The hybrid ML-DSA+Ed25519 combo is NOT a registered
    JOSE alg, so it can't ride as the envelope signature; it rides alongside.

Atlas is its own trust root: verifiers chain to the Atlas issuer key.

DISCIPLINE: `claims` carries verdicts / commitments / handles ONLY — never secret
key material, never raw biosignals, never plaintext.
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from dilithium_py.ml_dsa import ML_DSA_65

from ..crypto.primitives import H
from ..crypto.sign import HybridSigKeypair, HybridSigPublic

# claim types
CLAIM_LIVE_HUMAN = "atlas/live-human"
CLAIM_PROOF_OF_EXPERIENCE = "atlas/proof-of-experience"
CLAIM_VOUCH = "atlas/vouch"
CLAIM_CERT_VERDICT = "atlas/cert-verdict"


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def kid_of(pub: HybridSigPublic) -> str:
    """A short, stable issuer key id = first 16 bytes of H(domain || pubkey)."""
    return b64u(H(b"atlas/issuer-kid", pub.encode())[:16])


@dataclass
class AtlasAssertion:
    subject: str                      # handle / pseudonym / subject id the claim is about
    claim_type: str
    claims: dict[str, Any]            # VERDICTS ONLY — no secrets / raw / plaintext
    issued_at: float
    epoch: str                        # beacon/drand round (hex) — freshness / non-replay
    issuer_kid: str                   # Atlas issuer key id (kid_of)
    registry_ptr: Optional[str] = None

    def canonical(self) -> bytes:
        """Deterministic bytes both signatures cover (sorted keys, no whitespace)."""
        return json.dumps(
            {
                "sub": self.subject,
                "typ": self.claim_type,
                "claims": self.claims,
                "iat": self.issued_at,
                "epoch": self.epoch,
                "kid": self.issuer_kid,
                "reg": self.registry_ptr,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


@dataclass
class SignedAssertion:
    assertion: AtlasAssertion
    ed_sig: bytes       # standard EdDSA over canonical() — external-verifiable
    mldsa_sig: bytes    # embedded PQC binding over canonical() — Atlas-native


def issue(kp: HybridSigKeypair, assertion: AtlasAssertion) -> SignedAssertion:
    msg = assertion.canonical()
    return SignedAssertion(
        assertion=assertion,
        ed_sig=kp.ed_sk.sign(msg),
        mldsa_sig=ML_DSA_65.sign(kp.mldsa_sk, msg),
    )


def verify(pub: HybridSigPublic, signed: SignedAssertion, *, require_pqc: bool = True) -> bool:
    """Check the standard EdDSA signature (always) and the embedded ML-DSA binding
    (when require_pqc). External verifiers do the EdDSA half; Atlas does both."""
    msg = signed.assertion.canonical()
    try:
        Ed25519PublicKey.from_public_bytes(pub.ed_pk).verify(signed.ed_sig, msg)
    except InvalidSignature:
        return False
    if require_pqc and not ML_DSA_65.verify(pub.mldsa_pk, msg, signed.mldsa_sig):
        return False
    return True
