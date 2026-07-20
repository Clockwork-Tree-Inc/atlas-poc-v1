"""YubiKey Bio authorizes payments — no side button. The YubiKey's fingerprint-on-
key signature over THIS transaction IS the deliberate intent (the separate-device
isolation the side button lacks; iOS blocks the button for third parties anyway)."""

import os
import time

import pytest

from atlas.keys.hardware_key import FingerprintRequired, YubiKeyBio
from atlas.liveness.attestation import AttestationSubsystem
from atlas.liveness.bayes import LivenessGate
from atlas.liveness.synthetic import live_stream
from atlas.payment import (
    EnclaveArmingAuthority,
    NullifierRegistry,
    PaymentCard,
    PaymentVerifier,
    TransactionDescriptor,
)
from atlas.payment.yubikey_intent import (
    IntentRefused,
    intent_from_yubikey,
    payment_authorization_request,
)


def _descriptor(amount=1299, recipient="merchant-42", epoch=1):
    return TransactionDescriptor(amount=amount, recipient_id=recipient,
                                 nonce=os.urandom(16).hex(), timestamp=int(time.time()), epoch=epoch)


def _live(att):
    g = LivenessGate()
    for _, (psl, psnl) in live_stream(40):
        g.update(p_s_given_live=psl, p_s_given_not_live=psnl)
    return att.attest(g.state(sensor_digest=b"s", drand_round=b"\x00" * 8))


def test_yubikey_authorizes_a_payment_with_no_side_button():
    enclave = EnclaveArmingAuthority()
    card = PaymentCard(enclave_arming_public=enclave.public_key)
    att, yk = AttestationSubsystem(), YubiKeyBio()
    verifier = PaymentVerifier(NullifierRegistry())
    d = _descriptor()

    card_id, card_nonce = card.issue_challenge()
    # the YubiKey signs the payment authorization on-key (fingerprint) — NO button
    sig = yk.authorize(payment_authorization_request(d, card_nonce), fingerprint_matched=True)
    intent = intent_from_yubikey(descriptor=d, card_nonce=card_nonce, yubikey_public=yk.public, signature=sig)

    arming = enclave.mint(descriptor=d, card_id=card_id, card_nonce=card_nonce,
                          liveness=_live(att), intent=intent)
    card_sig = card.sign(d, arming)
    assert verifier.verify_and_submit(d, card_sig, card.public_key)


def test_no_fingerprint_no_payment_authorization():
    yk = YubiKeyBio()
    with pytest.raises(FingerprintRequired):
        yk.authorize(payment_authorization_request(_descriptor(), b"card-nonce"), fingerprint_matched=False)


def test_yubikey_signature_binds_to_this_exact_payment():
    yk = YubiKeyBio()
    d1, d2 = _descriptor(amount=100), _descriptor(amount=999_999)
    nonce = b"card-nonce-1"
    sig = yk.authorize(payment_authorization_request(d1, nonce), fingerprint_matched=True)
    # authorizes d1 only -> a different amount/descriptor is refused (no amount swap)
    with pytest.raises(IntentRefused):
        intent_from_yubikey(descriptor=d2, card_nonce=nonce, yubikey_public=yk.public, signature=sig)
    # and not replayable against a different card nonce
    with pytest.raises(IntentRefused):
        intent_from_yubikey(descriptor=d1, card_nonce=b"card-nonce-2", yubikey_public=yk.public, signature=sig)


def test_payment_routes_through_the_general_authenticator():
    """A payment is just action=authorize-transfer (step-up) in the verified-human
    authenticator — one path for everything, with amount binding preserved."""
    from atlas.auth import authenticate, verify_assertion
    from atlas.keys.identity import build_identity_tree
    from atlas.liveness.bayes import LivenessGate
    from atlas.liveness.synthetic import live_stream
    from atlas.payment.yubikey_intent import payment_auth_challenge

    g = LivenessGate()
    for _, (a, b) in live_stream(40):
        g.update(p_s_given_live=a, p_s_given_not_live=b)
    pole = g.state(sensor_digest=b"s", drand_round=b"\x00" * 8)

    user = build_identity_tree(os.urandom(32)).child("authorship")
    yk = YubiKeyBio()
    d = _descriptor(amount=5000)
    ch = payment_auth_challenge(d, b"card-nonce-1")
    assertion = authenticate(ch, authorship=user, pole=pole, yubikey=yk, fingerprint_matched=True)
    assert verify_assertion(assertion, ch, registered_handle=user.handle,
                            registered_public=user.public, registered_step_up_public=yk.public)
    # a different amount -> different descriptor -> different challenge -> won't verify
    ch_swapped = payment_auth_challenge(_descriptor(amount=999_999), b"card-nonce-1")
    assert not verify_assertion(assertion, ch_swapped, registered_handle=user.handle,
                                registered_public=user.public, registered_step_up_public=yk.public)
