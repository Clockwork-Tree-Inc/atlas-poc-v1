"""YubiKey Bio — high-stakes authorization gated by the on-key fingerprint, and
share-holding. Fail-closed without the fingerprint; signatures bind the exact
action (no replay)."""

import pytest

from atlas.crypto import shamir
from atlas.keys.hardware_key import (
    FingerprintRequired,
    HardwareKeyRefused,
    HighStakesRequest,
    YubiKeyBio,
    verify_high_stakes,
)


def _req(action="recover", context=b"ctx", challenge=b"nonce-1"):
    return HighStakesRequest(action=action, context=context, challenge=challenge)


def test_authorized_with_fingerprint_verifies():
    key = YubiKeyBio()
    req = _req()
    sig = key.authorize(req, fingerprint_matched=True)
    assert verify_high_stakes(key.public, req, sig)


def test_no_fingerprint_refuses_to_sign():
    key = YubiKeyBio()
    with pytest.raises(FingerprintRequired):
        key.authorize(_req(), fingerprint_matched=False)


def test_signature_does_not_verify_for_a_different_action():
    key = YubiKeyBio()
    sig = key.authorize(_req(action="recover", challenge=b"n1"), fingerprint_matched=True)
    # same key + signature, but a different action / context / challenge -> rejected
    assert not verify_high_stakes(key.public, _req(action="transfer", challenge=b"n1"), sig)
    assert not verify_high_stakes(key.public, _req(action="recover", challenge=b"n2"), sig)
    assert not verify_high_stakes(key.public, _req(action="recover", context=b"other", challenge=b"n1"), sig)


def test_wrong_key_does_not_verify():
    a, b = YubiKeyBio(), YubiKeyBio()
    req = _req()
    sig = a.authorize(req, fingerprint_matched=True)
    assert not verify_high_stakes(b.public, req, sig)      # attacker's key can't stand in


def test_recovery_share_release_is_fingerprint_gated():
    key = YubiKeyBio()
    share = shamir.split(b"S" * 32, n=3, k=2)[0]
    key.hold_recovery_share(share)
    with pytest.raises(FingerprintRequired):
        key.release_recovery_share(fingerprint_matched=False)
    assert key.release_recovery_share(fingerprint_matched=True).encode() == share.encode()


def test_release_with_no_share_refuses():
    with pytest.raises(HardwareKeyRefused):
        YubiKeyBio().release_recovery_share(fingerprint_matched=True)
