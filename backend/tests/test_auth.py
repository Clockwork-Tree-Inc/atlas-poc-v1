"""Atlas as the verified-human authenticator for a relying party (a bank, anything).
Passkey-shaped: register a key, answer a challenge with a live, presence-gated,
optionally YubiKey-stepped-up assertion. Relay-resistant and fail-closed."""

import os

import pytest

from atlas.auth import AuthChallenge, AuthRefused, authenticate, verify_assertion
from atlas.keys.hardware_key import FingerprintRequired, YubiKeyBio
from atlas.keys.identity import build_identity_tree
from atlas.liveness.bayes import LivenessGate, PoLEState
from atlas.liveness.synthetic import live_stream


def _live_pole(epoch=b"\x00" * 8):
    g = LivenessGate()
    for _, (psl, psnl) in live_stream(40):
        g.update(p_s_given_live=psl, p_s_given_not_live=psnl)
    return g.state(sensor_digest=b"s", drand_round=epoch)


def _dead_pole(epoch=b"\x00" * 8):
    return PoLEState(p_live=0.0, state_digest=b"d", drand_round=epoch, operate=False)


def _user():
    return build_identity_tree(os.urandom(32)).child("authorship")


def _chal(rp="acme-bank", action="login", step_up=False):
    return AuthChallenge(relying_party=rp, action=action, challenge=os.urandom(16), require_step_up=step_up)


# -- routine authentication (login) ------------------------------------------

def test_registered_user_authenticates():
    user = _user()
    ch = _chal()
    assertion = authenticate(ch, authorship=user, pole=_live_pole())
    assert verify_assertion(assertion, ch, registered_handle=user.handle, registered_public=user.public)


def test_no_live_presence_fails_closed():
    with pytest.raises(AuthRefused):
        authenticate(_chal(), authorship=_user(), pole=_dead_pole())


def test_assertion_cannot_be_relayed_to_a_different_relying_party():
    """Phishing/relay resistance: a proof made for acme-bank must NOT authenticate to
    evil-bank — the relying party is bound into the assertion."""
    user = _user()
    ch = _chal(rp="acme-bank")
    assertion = authenticate(ch, authorship=user, pole=_live_pole())
    evil = AuthChallenge(relying_party="evil-bank", action="login", challenge=ch.challenge)
    assert not verify_assertion(assertion, evil, registered_handle=user.handle, registered_public=user.public)


def test_wrong_registered_key_is_rejected():
    user, stranger = _user(), _user()
    ch = _chal()
    assertion = authenticate(ch, authorship=user, pole=_live_pole())
    assert not verify_assertion(assertion, ch, registered_handle=stranger.handle, registered_public=stranger.public)


def test_tampered_assertion_is_rejected():
    user = _user()
    ch = _chal()
    assertion = authenticate(ch, authorship=user, pole=_live_pole())
    assertion.signature = assertion.signature[:-1] + bytes([assertion.signature[-1] ^ 1])
    assert not verify_assertion(assertion, ch, registered_handle=user.handle, registered_public=user.public)


# -- high-assurance step-up (YubiKey) ----------------------------------------

def test_step_up_action_requires_yubikey():
    with pytest.raises(AuthRefused):                    # RP requires step-up, none supplied
        authenticate(_chal(action="authorize-transfer", step_up=True), authorship=_user(), pole=_live_pole())


def test_step_up_without_fingerprint_refuses():
    with pytest.raises(FingerprintRequired):
        authenticate(_chal(action="authorize-transfer", step_up=True), authorship=_user(),
                     pole=_live_pole(), yubikey=YubiKeyBio(), fingerprint_matched=False)


def test_step_up_with_yubikey_verifies():
    user, yk = _user(), YubiKeyBio()
    ch = _chal(action="authorize-transfer", step_up=True)
    assertion = authenticate(ch, authorship=user, pole=_live_pole(), yubikey=yk, fingerprint_matched=True)
    assert verify_assertion(assertion, ch, registered_handle=user.handle, registered_public=user.public,
                            registered_step_up_public=yk.public)


def test_attackers_yubikey_cannot_stand_in_for_the_registered_one():
    user, yk, attacker_yk = _user(), YubiKeyBio(), YubiKeyBio()
    ch = _chal(action="authorize-transfer", step_up=True)
    assertion = authenticate(ch, authorship=user, pole=_live_pole(), yubikey=yk, fingerprint_matched=True)
    # verifier registered a DIFFERENT YubiKey -> the assertion's step-up key doesn't match
    assert not verify_assertion(assertion, ch, registered_handle=user.handle, registered_public=user.public,
                                registered_step_up_public=attacker_yk.public)


def test_step_up_required_but_assertion_not_stepped_up_is_rejected():
    user = _user()
    nonce = os.urandom(16)
    # assertion made for a NON-step-up challenge (same nonce)
    assertion = authenticate(AuthChallenge("acme-bank", "authorize-transfer", nonce, require_step_up=False),
                             authorship=user, pole=_live_pole())
    # RP required a step-up -> a non-stepped assertion must not pass
    required = AuthChallenge("acme-bank", "authorize-transfer", nonce, require_step_up=True)
    assert not verify_assertion(assertion, required, registered_handle=user.handle,
                                registered_public=user.public, registered_step_up_public=b"whatever")
