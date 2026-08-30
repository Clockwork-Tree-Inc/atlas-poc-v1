"""Enclave-side arming authority (Payment spec §4 steps 2–4).

The Secure Enclave mints an arming token bound to THIS transaction AND THIS card,
only after the Atlas verified-human check passes: a current liveness attestation
(ring + Enclave) AND a deliberate side-button intent press. It authorizes exactly
one signature, for this descriptor only.

  arming = Sign_Enclave( H(transaction_descriptor) || card_id || card_nonce )

The Enclave holds NO card key. The card holds only the Enclave PUBLIC key (to
verify armings). Classical Ed25519 is used so a prototype JavaCard can verify it
on-card (spec §7.3: classical on-card acceptable; PQC-on-card is production).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ..crypto.primitives import H
from ..liveness.attestation import LivenessAttestation
from .descriptor import TransactionDescriptor
from .intent import IntentToken


class ArmingRefused(Exception):
    """The verified-human gate failed — no arming is issued (spec §4 step 2)."""


@dataclass(frozen=True)
class Arming:
    """One-shot authorization for a single card signature."""

    signature: bytes        # Ed25519 over H(descriptor)||card_id||card_nonce
    descriptor_hash: bytes  # H(descriptor.canonical()) — for transport/audit only
    card_id: bytes
    card_nonce: bytes


def arming_message(descriptor: TransactionDescriptor, card_id: bytes, card_nonce: bytes) -> bytes:
    return H(b"atlas/arming", descriptor.canonical()) + card_id + card_nonce


class EnclaveArmingAuthority:
    """Secure-Enclave-resident arming key. Models a non-extractable Enclave key;
    no path exports the private half."""

    def __init__(self):
        self._key = Ed25519PrivateKey.generate()

    @property
    def public_key(self) -> bytes:
        """Enrolled on the card so it can verify armings."""
        return self._key.public_key().public_bytes_raw()

    def mint(
        self,
        *,
        descriptor: TransactionDescriptor,
        card_id: bytes,
        card_nonce: bytes,
        liveness: Optional[LivenessAttestation],
        intent: Optional[IntentToken],
        require_co_motion: bool = False,
    ) -> Arming:
        # §4 step 2 — verified-human gate: liveness AND deliberate intent press.
        if liveness is None or not liveness.verify() or not liveness.operate:
            raise ArmingRefused("no current liveness attestation")
        if intent is None:
            raise ArmingRefused("no side-button intent press")
        if require_co_motion and not intent.co_motion_confirmed:
            raise ArmingRefused("high-assurance mode requires ring co-motion confirmation")
        if not descriptor.well_formed():
            raise ArmingRefused("malformed transaction descriptor")

        msg = arming_message(descriptor, card_id, card_nonce)
        sig = self._key.sign(msg)
        return Arming(signature=sig, descriptor_hash=H(b"atlas/arming", descriptor.canonical()),
                      card_id=card_id, card_nonce=card_nonce)
