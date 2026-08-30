"""WebAuthn mapping (the passkey bridge) — the SHAPE, not a full stack.

Existing banks consume Atlas as a passkey provider. WebAuthn's data shapes map onto
our authenticator 1:1:

  * clientDataJSON = {"type": "webauthn.get", "challenge": <b64url RP nonce>,
    "origin": <relying party>} — our `AuthChallenge.challenge` IS the WebAuthn
    challenge, and our `relying_party` binding IS the WebAuthn ORIGIN (that origin
    binding is exactly WebAuthn's phishing resistance, which we already enforce in
    `verify_assertion`).
  * the assertion signature is over authenticatorData || SHA256(clientDataJSON),
    produced ONLY AFTER Atlas's gate (live presence + optional YubiKey step-up). That
    "gate before signing" is the whole Face-ID+ value — to the bank it's a standard
    passkey; underneath it's liveness + presence + hardware.

HONEST BOUNDARY: this is the FORMAT MAPPING, not a WebAuthn implementation. Production
uses a VETTED WebAuthn stack — `AuthenticationServices` (an
`ASCredentialProviderExtension`) on device, and a WebAuthn server lib on the relying
party — for the real CBOR / COSE keys / attestation. Do NOT hand-roll WebAuthn crypto
(Step-Zero rule). This module only pins how our fields correspond, so the device work
and the RP work agree on the wire.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Optional

from ..crypto.sign import HybridSigKeypair, HybridSigPublic
from ..interop._jws import pqc_binding, sign_compact, verify_compact
from ..interop.assertion import CLAIM_LIVE_HUMAN, AtlasAssertion, kid_of
from .relying_party import AuthChallenge


def b64url(b: bytes) -> str:
    """WebAuthn uses base64url WITHOUT padding."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def client_data_json(challenge: bytes, origin: str, *, ceremony: str = "webauthn.get") -> bytes:
    """The WebAuthn clientDataJSON the relying party binds. `origin` is the RP
    identity (phishing binding); `challenge` is the RP nonce."""
    return json.dumps({"type": ceremony, "challenge": b64url(challenge), "origin": origin},
                      separators=(",", ":")).encode()


def client_data_hash(challenge: bytes, origin: str, *, ceremony: str = "webauthn.get") -> bytes:
    return hashlib.sha256(client_data_json(challenge, origin, ceremony=ceremony)).digest()


def challenge_to_client_data(ch: AuthChallenge) -> bytes:
    """Map our AuthChallenge to WebAuthn clientDataJSON: relying_party -> origin,
    challenge -> challenge. The signed-over hash is `client_data_hash`; the actual
    signature is produced by the passkey key AFTER Atlas's gate."""
    return client_data_json(ch.challenge, ch.relying_party)


# -- authenticatorData byte layout (data-format, not crypto) --------------------
#
# WebAuthn authenticatorData begins with a FIXED layout:
#   rpIdHash(32) || flags(1) || signCount(4, big-endian) [ || attestedCredentialData
#   || extensions ]. The head is plain serialization; the attested-credential-data
#   (COSE credential public key) and the CBOR extensions block are appended by a
#   VETTED WebAuthn stack (Step-Zero) — this module never hand-rolls that CBOR/COSE.

FLAG_UP = 0x01  # user present
FLAG_UV = 0x04  # user verified (Atlas's live-presence gate maps here)
FLAG_AT = 0x40  # attested credential data included (added by the vetted stack)
FLAG_ED = 0x80  # extension data included (added by the vetted stack)


def authenticator_data(rp_id: str, *, user_present: bool = True,
                       user_verified: bool = True, sign_count: int = 0) -> bytes:
    """The fixed-layout head of WebAuthn authenticatorData:
    SHA256(rpId) || flags || signCount(4, big-endian)."""
    rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
    flags = (FLAG_UP if user_present else 0) | (FLAG_UV if user_verified else 0)
    return rp_id_hash + bytes([flags & 0xFF]) + int(sign_count).to_bytes(4, "big")


def signed_over(authenticator_data_bytes: bytes, client_data_hash_bytes: bytes) -> bytes:
    """What a WebAuthn credential signs: authenticatorData || clientDataHash."""
    return authenticator_data_bytes + client_data_hash_bytes


# -- the Atlas verified-human WebAuthn EXTENSION (the Atlas-specific interop piece) --
#
# A WebAuthn ceremony proves possession of a credential key; it does NOT prove a live
# human is present. Atlas supplies exactly that missing guarantee via a client
# extension `atlasVerifiedHuman`: the authenticator returns, in clientExtensionResults,
# an EdDSA-signed compact JWS — the SAME envelope the VC/OIDC adapters use (registered
# alg + embedded ML-DSA post-quantum binding) — asserting a verified live human, BOUND
# to the RP's WebAuthn challenge and origin (anti-replay + phishing binding). The
# relying party reads clientExtensionResults[ATLAS_WEBAUTHN_EXTENSION] and verifies it
# against Atlas's published key (did:atlas), chaining to Atlas as its own root — exactly
# like every other Atlas adapter. This is the Atlas-specific format mapping ONLY; the
# CBOR attestationObject / COSE keys / attestation statement come from a vetted stack.

ATLAS_WEBAUTHN_EXTENSION = "atlasVerifiedHuman"


def atlas_extension_output(
    kp: HybridSigKeypair,
    *,
    subject: str,
    challenge: bytes,
    origin: str,
    epoch: str,
    issued_at: float,
    ceremony: str = "webauthn.create",
) -> str:
    """Produce the `atlasVerifiedHuman` client-extension output (a compact JWS) an
    authenticator returns after Atlas's live-presence gate. Bound to the WebAuthn
    challenge + origin."""
    kid = kid_of(kp.public)
    assertion = AtlasAssertion(
        subject=subject,
        claim_type=CLAIM_LIVE_HUMAN,
        claims={"origin": origin, "challenge": b64url(challenge), "ceremony": ceremony},
        issued_at=issued_at,
        epoch=epoch,
        issuer_kid=kid,
    )
    canonical = assertion.canonical()
    header = {"alg": "EdDSA", "typ": "atlas-webauthn-ext+jwt", "kid": kid}
    payload: dict[str, Any] = {
        "iss": "did:atlas:" + kid,
        "sub": subject,
        "iat": int(issued_at),
        "atlas_verified_human": True,
        "origin": origin,
        "challenge": b64url(challenge),
        "ceremony": ceremony,
        "epoch": epoch,
        "atlas": pqc_binding(kp, canonical),
    }
    return sign_compact(kp, header, payload)


def verify_atlas_extension(
    pub: HybridSigPublic,
    output: str,
    *,
    challenge: Optional[bytes] = None,
    origin: Optional[str] = None,
    require_pqc: bool = True,
) -> Optional[dict]:
    """Relying-party side. Verify the extension output (EdDSA + embedded ML-DSA) and,
    when supplied, that it is bound to THIS WebAuthn challenge and origin (anti-replay,
    phishing-resistant). Returns the payload or None (fail-closed)."""
    payload = verify_compact(pub, output, require_pqc=require_pqc)
    if payload is None:
        return None
    if payload.get("atlas_verified_human") is not True:
        return None
    if challenge is not None and payload.get("challenge") != b64url(challenge):
        return None
    if origin is not None and payload.get("origin") != origin:
        return None
    return payload
