"""Submit-side verification + nullifier (Payment spec §4 steps 7–8).

Two independent single-use guards (§4 step 8):
  * the card consumes its card_nonce (no arming replay) — enforced in card.py;
  * the verifier nullifies the descriptor nonce (no descriptor re-submit) — here.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .descriptor import TransactionDescriptor


class DoubleSpend(Exception):
    """The descriptor nonce was already spent (nullifier)."""


class NullifierRegistry:
    def __init__(self):
        self._spent: set[str] = set()

    def is_spent(self, nonce: str) -> bool:
        return nonce in self._spent

    def nullify(self, nonce: str) -> None:
        self._spent.add(nonce)


class PaymentVerifier:
    """Checks payment_sig against the card's enrolled public key and that the
    nonce is unspent, then nullifies it (§4 step 7)."""

    def __init__(self, registry: NullifierRegistry):
        self._registry = registry

    def verify_and_submit(self, descriptor: TransactionDescriptor, payment_sig: bytes,
                          card_public: bytes) -> bool:
        if self._registry.is_spent(descriptor.nonce):
            raise DoubleSpend("descriptor nonce already spent")
        try:
            Ed25519PublicKey.from_public_bytes(card_public).verify(payment_sig, descriptor.canonical())
        except InvalidSignature:
            return False
        self._registry.nullify(descriptor.nonce)
        return True
