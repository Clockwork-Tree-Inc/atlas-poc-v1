"""YubiKey Bio as the payment intent gate — no side button needed.

The Payment spec always called the side-button press a "YubiKey-touch replacement"
(intent.py) and noted the button does NOT give separate-device isolation — that was
always the external factor's job. Now that the YubiKey Bio factor exists
(keys/hardware_key.py), it IS the deliberate intent for a payment: a
fingerprint-on-key signature over THIS transaction. This is strictly better than the
side button, which iOS blocks for third parties (only Apple Pay gets it) — and it
adds the separate-device isolation the button lacks.

FLOW: the card issues a fresh nonce; the YubiKey signs the payment-authorization
request (bound to the descriptor + that nonce, gated by the on-key fingerprint); the
verified signature mints the IntentToken the EnclaveArmingAuthority consumes. No
button anywhere. Fail-closed: no fingerprint -> no signature -> no intent -> no
arming.
"""

from __future__ import annotations

from ..crypto.primitives import H
from ..keys.hardware_key import HighStakesRequest, verify_high_stakes
from .descriptor import TransactionDescriptor
from .intent import IntentToken


class IntentRefused(Exception):
    """The YubiKey did not authorize this payment (no valid fingerprint-gated
    signature over this exact transaction) — no intent, fail-closed."""


def payment_authorization_request(descriptor: TransactionDescriptor, card_nonce: bytes) -> HighStakesRequest:
    """The high-stakes request the YubiKey signs to authorize THIS payment: the
    action bound to the descriptor and the fresh card nonce (anti-replay). Build it
    identically on both sides so the signature verifies."""
    return HighStakesRequest(action="payment",
                             context=H(b"atlas/pay-intent", descriptor.canonical()),
                             challenge=card_nonce)


def intent_from_yubikey(*, descriptor: TransactionDescriptor, card_nonce: bytes,
                        yubikey_public: bytes, signature: bytes,
                        co_motion_confirmed: bool = False) -> IntentToken:
    """Verify the YubiKey's fingerprint-gated authorization over this payment and, on
    success, mint the deliberate-intent token the arming authority consumes. A
    signature for a different descriptor/nonce does not verify -> IntentRefused."""
    req = payment_authorization_request(descriptor, card_nonce)
    if not verify_high_stakes(yubikey_public, req, signature):
        raise IntentRefused("YubiKey did not authorize this payment")
    # bind the intent's nonce to the card nonce so the whole arming is single-use.
    return IntentToken(nonce=card_nonce, co_motion_confirmed=co_motion_confirmed)


# -- unified path: a payment is just an auth ACTION -----------------------------

def payment_auth_challenge(descriptor: TransactionDescriptor, card_nonce: bytes,
                           *, relying_party: str = "atlas-merchant"):
    """A payment authorization is the SAME verified-human authenticator as everything
    else — action `authorize-transfer`, step-up required, with the transaction
    descriptor bound into the challenge. Routes payments through auth/relying_party.py
    (one clean path) instead of a payment-only signature."""
    from ..auth.relying_party import AuthChallenge
    challenge = H(b"atlas/pay-auth", descriptor.canonical(), card_nonce)
    return AuthChallenge(relying_party=relying_party, action="authorize-transfer",
                         challenge=challenge, require_step_up=True)
