"""Card 2 — the air-gapped payment card (Payment spec §2, §4 steps 4–6).

⚠️ MODEL of the JavaCard applet for protocol-logic testing — NOT the air gap.
The real Card 2 is a physical JavaCard; on hardware the private key is generated
on-card in a secure element and never leaves. Here we *model* non-extractability
by holding the key inside this object with no export path (asserted by tests).

The card is dormant and unpowered except during the tap. It:
  * issues a fresh card_nonce per tap (mutual freshness, §4 step 4),
  * verifies the arming's Enclave signature, that card_nonce matches the one it
    just issued, and that the descriptor is well-formed (§4 step 5),
  * signs exactly ONE transaction per arming, then discards the card_nonce.

Classical Ed25519 on-card signer (spec §7.3: classical acceptable for prototype).
"""

from __future__ import annotations

from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ..crypto.primitives import random_bytes
from .descriptor import TransactionDescriptor
from .enclave_arming import Arming, arming_message


class CardRefused(Exception):
    """The card refused to sign (bad/stale arming, replay, malformed)."""


class PaymentCard:
    def __init__(self, enclave_arming_public: bytes, card_id: Optional[bytes] = None):
        # On-card key generation; the private half is never exported.
        self.__signing_key = Ed25519PrivateKey.generate()
        self.card_id = card_id or random_bytes(8)
        self._enclave_pub = Ed25519PublicKey.from_public_bytes(enclave_arming_public)
        self._pending_nonce: Optional[bytes] = None

    @property
    def public_key(self) -> bytes:
        """The card's payment public key, enrolled with the verifier."""
        return self.__signing_key.public_key().public_bytes_raw()

    # §4 step 4 — mutual freshness: the card issues the nonce the arming must bind.
    def issue_challenge(self) -> tuple[bytes, bytes]:
        self._pending_nonce = random_bytes(16)
        return self.card_id, self._pending_nonce

    # §4 step 6 — verify the arming, then sign exactly one transaction.
    def sign(self, descriptor: TransactionDescriptor, arming: Arming) -> bytes:
        if self._pending_nonce is None:
            raise CardRefused("no fresh card_nonce issued (card not armed this tap)")
        # Consume the nonce up front: ANY processing of an arming this tap retires
        # the challenge, so a failed/replayed attempt cannot be retried against the
        # same nonce (security review — don't leave the nonce live on the error
        # paths). The caller must re-issue a fresh challenge to try again.
        pending = self._pending_nonce
        self._pending_nonce = None
        if arming.card_id != self.card_id:
            raise CardRefused("arming bound to a different card")
        if arming.card_nonce != pending:
            raise CardRefused("arming card_nonce does not match the one just issued")
        if not descriptor.well_formed():
            raise CardRefused("malformed descriptor")
        msg = arming_message(descriptor, self.card_id, pending)
        try:
            self._enclave_pub.verify(arming.signature, msg)
        except InvalidSignature:
            raise CardRefused("invalid Enclave arming signature")

        # nonce already consumed above; single signature per arming (§4 step 8).
        return self.__signing_key.sign(descriptor.canonical())
