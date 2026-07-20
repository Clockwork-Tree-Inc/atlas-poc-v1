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
