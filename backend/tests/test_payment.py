"""Air-gapped payment — adversarial tests (Payment spec §7.2).

These test the PROTOCOL LOGIC of the arm-per-use flow. They do NOT prove the
air gap (that needs the physical card + Step Zero on hardware). They are the
"assistant writes adversarial tests" deliverable handed to the reviewer (§8).
"""

import os
import time

import pytest

from atlas.liveness.attestation import AttestationSubsystem
from atlas.liveness.bayes import LivenessGate
from atlas.liveness.synthetic import live_stream, spoof_stream
from atlas.payment import (
    Arming, ArmingRefused, CardRefused, DoubleSpend, EnclaveArmingAuthority,
    NullifierRegistry, PaymentCard, PaymentVerifier, SideButtonIntent, TransactionDescriptor,
)


def _live(att, drand_round=b"\x00" * 8):
    g = LivenessGate()
    for _, (psl, psnl) in live_stream(40):
        g.update(p_s_given_live=psl, p_s_given_not_live=psnl)
    return att.attest(g.state(sensor_digest=b"s", drand_round=drand_round))


def _descriptor(amount=1299, recipient="merchant-42", nonce=None, epoch=1):
    return TransactionDescriptor(amount=amount, recipient_id=recipient,
                                 nonce=nonce or os.urandom(16).hex(), timestamp=int(time.time()), epoch=epoch)


def _kit():
    enclave = EnclaveArmingAuthority()
    card = PaymentCard(enclave_arming_public=enclave.public_key)
    att = AttestationSubsystem()
    button = SideButtonIntent()
    registry = NullifierRegistry()
    verifier = PaymentVerifier(registry)
    return enclave, card, att, button, registry, verifier


def _happy_path(enclave, card, att, button, descriptor, require_co_motion=False, co_motion=False):
    card_id, card_nonce = card.issue_challenge()
    arming = enclave.mint(descriptor=descriptor, card_id=card_id, card_nonce=card_nonce,
                          liveness=_live(att), intent=button.press(co_motion_confirmed=co_motion),
                          require_co_motion=require_co_motion)
    return card.sign(descriptor, arming)


def test_happy_path_round_trip():
    enclave, card, att, button, registry, verifier = _kit()
    d = _descriptor()
    sig = _happy_path(enclave, card, att, button, d)
    assert verifier.verify_and_submit(d, sig, card.public_key)


# -- §7.2 air-gap holds -----------------------------------------------------

def test_stolen_card_alone_cannot_sign():
    """Stolen card + no phone -> no arming -> cannot produce a usable signature."""
    enclave, card, att, button, registry, verifier = _kit()
    d = _descriptor()
    card_id, card_nonce = card.issue_challenge()
    # Attacker has the card but no Enclave arming. Forge an arming with a random key.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    forged = Ed25519PrivateKey.generate()
    from atlas.payment.enclave_arming import arming_message
    bad = Arming(signature=forged.sign(arming_message(d, card_id, card_nonce)),
                 descriptor_hash=b"", card_id=card_id, card_nonce=card_nonce)
    with pytest.raises(CardRefused):
        card.sign(d, bad)


def test_compromised_phone_alone_cannot_sign():
    """Compromised phone + no card -> can mint armings but cannot produce a
    payment signature (no card key)."""
    enclave, card, att, button, registry, verifier = _kit()
    d = _descriptor()
    # The phone can mint an arming, but without the card there is no payment_sig.
    # A forged "payment signature" from a non-card key fails verification.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    attacker = Ed25519PrivateKey.generate()
    forged_payment_sig = attacker.sign(d.canonical())
    assert verifier.verify_and_submit(d, forged_payment_sig, card.public_key) is False


# -- §7.2 no replay ---------------------------------------------------------

def test_used_arming_cannot_be_re_presented_to_card():
    enclave, card, att, button, registry, verifier = _kit()
    d = _descriptor()
    card_id, card_nonce = card.issue_challenge()
    arming = enclave.mint(descriptor=d, card_id=card_id, card_nonce=card_nonce,
                          liveness=_live(att), intent=button.press())
    card.sign(d, arming)                       # consumes the card_nonce
    with pytest.raises(CardRefused):           # re-presenting the same arming
        card.sign(d, arming)


def test_used_descriptor_cannot_be_resubmitted():
    enclave, card, att, button, registry, verifier = _kit()
    d = _descriptor()
    sig = _happy_path(enclave, card, att, button, d)
    assert verifier.verify_and_submit(d, sig, card.public_key)
    with pytest.raises(DoubleSpend):
        verifier.verify_and_submit(d, sig, card.public_key)


# -- §7.2 binding -----------------------------------------------------------

def test_arming_for_A_cannot_authorize_B():
    enclave, card, att, button, registry, verifier = _kit()
    a, b = _descriptor(amount=100), _descriptor(amount=999999)
    card_id, card_nonce = card.issue_challenge()
    arming_a = enclave.mint(descriptor=a, card_id=card_id, card_nonce=card_nonce,
                            liveness=_live(att), intent=button.press())
    with pytest.raises(CardRefused):           # present descriptor B with A's arming
        card.sign(b, arming_a)


def test_arming_for_card_X_cannot_be_used_on_card_Y():
    enclave, _, att, button, registry, verifier = _kit()
    card_x = PaymentCard(enclave_arming_public=enclave.public_key)
    card_y = PaymentCard(enclave_arming_public=enclave.public_key)
    d = _descriptor()
    x_id, x_nonce = card_x.issue_challenge()
    arming_x = enclave.mint(descriptor=d, card_id=x_id, card_nonce=x_nonce,
                            liveness=_live(att), intent=button.press())
    card_y.issue_challenge()
    with pytest.raises(CardRefused):
        card_y.sign(d, arming_x)


# -- §7.2 intent + liveness required ----------------------------------------

def test_no_side_button_press_no_arming():
    enclave, card, att, button, registry, verifier = _kit()
    d = _descriptor()
    card_id, card_nonce = card.issue_challenge()
    with pytest.raises(ArmingRefused):
        enclave.mint(descriptor=d, card_id=card_id, card_nonce=card_nonce,
                     liveness=_live(att), intent=None)


def test_no_liveness_no_arming():
    enclave, card, att, button, registry, verifier = _kit()
    d = _descriptor()
    card_id, card_nonce = card.issue_challenge()
    with pytest.raises(ArmingRefused):
        enclave.mint(descriptor=d, card_id=card_id, card_nonce=card_nonce,
                     liveness=None, intent=button.press())
    # a broken-liveness (spoof) attestation is also refused
    g = LivenessGate()
    for _, (psl, psnl) in spoof_stream(40):
        g.update(p_s_given_live=psl, p_s_given_not_live=psnl)
    spoof = att.attest(g.state(sensor_digest=b"s", drand_round=b"\x00" * 8))  # None (break)
    with pytest.raises(ArmingRefused):
        enclave.mint(descriptor=d, card_id=card_id, card_nonce=card_nonce,
                     liveness=spoof, intent=button.press())


def test_high_assurance_requires_co_motion():
    enclave, card, att, button, registry, verifier = _kit()
    d = _descriptor()
    card_id, card_nonce = card.issue_challenge()
    with pytest.raises(ArmingRefused):         # co-motion required but not confirmed
        enclave.mint(descriptor=d, card_id=card_id, card_nonce=card_nonce,
                     liveness=_live(att), intent=button.press(co_motion_confirmed=False),
                     require_co_motion=True)
    # confirmed co-motion passes
    sig = _happy_path(enclave, card, att, button, d, require_co_motion=True, co_motion=True)
    assert verifier.verify_and_submit(d, sig, card.public_key)


# -- §7.2 key never leaves --------------------------------------------------

def test_card_private_key_has_no_export_path():
    enclave, card, att, button, registry, verifier = _kit()
    # No public attribute or method returns private key material.
    assert not hasattr(card, "private_key")
    publicish = [a for a in dir(card) if not a.startswith("_PaymentCard__")]
    for name in publicish:
        assert "private" not in name.lower()
    # The name-mangled key is an Ed25519 private object, never returned by the API.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    assert isinstance(card._PaymentCard__signing_key, Ed25519PrivateKey)


def test_enclave_arming_key_not_exported():
    enclave = EnclaveArmingAuthority()
    assert not hasattr(enclave, "private_key")
    # only the public key is exposed
    assert isinstance(enclave.public_key, (bytes, bytearray)) and len(enclave.public_key) == 32
