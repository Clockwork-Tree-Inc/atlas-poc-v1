"""YubiKey Bio — the high-stakes hardware factor.

ROLE SEPARATION (see NAMING.md): unlike the ring (a liveness sensor that holds NO
secrets), the YubiKey is a deliberate, rarely-touched SECRET-HOLDER. Its two jobs:

  1. HIGH-STAKES AUTHORIZATION — sign a high-risk action (recovery, identity
     rotation, large transfer) with a non-extractable key, gated by the YubiKey's
     OWN on-key fingerprint. The biometric never leaves the key; the phone/relay
     only ever sees a signature over the specific action.
  2. SHARE-HOLDER — optionally hold a recovery Shamir share, released only on the
     same on-key fingerprint.

The signature binds (action, context, fresh challenge), so it cannot be replayed
onto a different action or a later request. Fail-closed: no fingerprint, no
signature.

HONEST BOUNDARY: the real key is non-extractable hardware (YubiKit / the YubiKey's
secure element) and the fingerprint match happens ON the key. This models the
protocol with Ed25519 (classical acceptable for the prototype, per the payment
spec); `fingerprint_matched` stands in for the on-key biometric gate.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ..crypto import shamir
from ..crypto.primitives import H


class FingerprintRequired(Exception):
    """The YubiKey's on-key fingerprint did not match — refuse to sign/release."""


class HardwareKeyRefused(Exception):
    """The YubiKey refused (nothing held, malformed request)."""


@dataclass(frozen=True)
class HighStakesRequest:
    """A high-risk action to authorize. `challenge` is a FRESH nonce from the
    verifier (anti-replay); `context` binds the specific operation."""

    action: str            # e.g. "recover", "rotate-identity", "transfer"
    context: bytes         # binds the exact operation (recipient, amount, epoch, ...)
    challenge: bytes       # fresh verifier nonce

    def message(self) -> bytes:
        return H(b"atlas/high-stakes", self.action.encode(), self.context, self.challenge)


class YubiKeyBio:
    """Models a YubiKey Bio: a non-extractable Ed25519 signer whose signing (and
    share release) is gated by an on-key fingerprint match. The private key is never
    exposed (double-underscore name-mangled here; the real key never leaves the
    hardware)."""

    def __init__(self) -> None:
        self.__signing = Ed25519PrivateKey.generate()   # non-extractable (modeled)
        self._share: Optional[shamir.Share] = None

    @property
    def public(self) -> bytes:
        return self.__signing.public_key().public_bytes_raw()

    def authorize(self, request: HighStakesRequest, *, fingerprint_matched: bool) -> bytes:
        """Sign the high-stakes action iff the on-key fingerprint matched. The
        signature binds (action, context, challenge) — not replayable elsewhere."""
        if not fingerprint_matched:
            raise FingerprintRequired("YubiKey fingerprint not matched on-key")
        return self.__signing.sign(request.message())

    # -- optional recovery-share holder -------------------------------------

    def hold_recovery_share(self, share: shamir.Share) -> None:
        self._share = share

    def release_recovery_share(self, *, fingerprint_matched: bool) -> shamir.Share:
        if not fingerprint_matched:
            raise FingerprintRequired("YubiKey fingerprint not matched on-key")
        if self._share is None:
            raise HardwareKeyRefused("no recovery share held on this key")
        return self._share


def verify_high_stakes(public: bytes, request: HighStakesRequest, signature: bytes) -> bool:
    """Verifier side: the signature must be by THIS key over THIS exact request. A
    signature for a different action/context/challenge does not verify (anti-replay).
    Wrap one-shot actions in a ReplayCache (atlas.keys.tokens) for single use."""
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, request.message())
        return True
    except Exception:
        return False
