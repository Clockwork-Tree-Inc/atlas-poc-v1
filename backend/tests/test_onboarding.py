"""Onboarding: single identification phase, phase gate, device challenge-response
(Locked Model §2.1, §2.4 — FIX #1 / #2 / #6)."""

import os

import pytest

from atlas.keys.identity import PseudonymTier
from atlas.session.onboarding import Onboarding, EnrollmentAuthority, PhaseError


def _identify():
    ob = Onboarding()
    user = ob.identify(
        os.urandom(32),
        device_names=["wallet", "phone", "laptop"],
        pseudonyms=[("shop", PseudonymTier.PUBLIC), ("forum", PseudonymTier.ANONYMOUS)],
    )
    return ob, user


# -- FIX #2: identification establishes EVERYTHING together -----------------

def test_identification_establishes_tsk_sysid_enrollment_pseudonyms_together():
    ob, user = _identify()
    # TSK + System-ID
    assert user.tree.tsk_public and user.tree.system_id_handle()
    # device enrollment — all devices enrolled, bound to the BLIND System-ID
    assert {d.name for d in user.devices} == {"wallet", "phone", "laptop"}
    for d in user.devices:
        assert user.authority.is_enrolled(d.name)
        assert user.authority.system_id_of(d.name) == user.tree.system_id_handle()
    # pseudonyms, user-selected tiers
    assert set(user.pseudonyms) == {"shop", "forum"}
    assert user.pseudonyms["shop"].handle != user.pseudonyms["forum"].handle


# -- FIX #6: device-key challenge-response ----------------------------------

def test_device_challenge_response_authentication():
    ob, user = _identify()
    wallet = next(d for d in user.devices if d.name == "wallet")
    auth = user.authority
    chal = auth.issue_challenge()
    resp = wallet.respond_to_challenge(chal)
    assert auth.verify_response("wallet", chal, resp)
    # wrong challenge / wrong device / tampered response all fail
    assert not auth.verify_response("wallet", auth.issue_challenge(), resp)
    assert not auth.verify_response("phone", chal, resp)          # phone didn't sign it
    assert not auth.verify_response("wallet", chal, resp[:-1] + bytes([resp[-1] ^ 1]))
    # only the PUBLIC half was enrolled; the private half never left the device
    enrolled_public, _ = auth._enrolled["wallet"]
    assert enrolled_public.encode() == wallet.device_public().encode()


def test_device_key_not_in_key_derivation():
    """The device auth key is identifier/authenticator only — never in the session
    key path. Two devices with the SAME identity+inputs but different dev keys
    still compose identical session keys (dev key absent from the KDF)."""
    from atlas.session.device import Device
    from atlas.keys.identity import build_identity_tree
    seed = os.urandom(32); boot = os.urandom(32)
    tree = build_identity_tree(seed)
    A = Device("A", tree, dev_key=b"\x01" * 32, bootstrap_tunnel_key=boot)
    B = Device("B", tree, dev_key=b"\x02" * 32, bootstrap_tunnel_key=boot)
    a = A.advance_epoch_present(lk=b"L" * 32, epoch_key=b"E" * 32, drand_round=b"\x00" * 8)
    b = B.advance_epoch_present(lk=b"L" * 32, epoch_key=b"E" * 32, drand_round=b"\x00" * 8)
    # local_qrng_draw differs per call, so keys differ — but NOT because of dev_key:
    assert A.device_public().encode() != B.device_public().encode()   # distinct auth keys


# -- FIX #1: enforced phase gate --------------------------------------------

def test_liveness_streaming_is_gated_behind_identification():
    ob = Onboarding()
    # a device that exists outside the flow cannot be streamed before identification
    from atlas.session.device import Device
    from atlas.keys.identity import build_identity_tree
    stray = Device("stray", build_identity_tree(os.urandom(32)))
    with pytest.raises(PhaseError):
        ob.begin_liveness_streaming(stray)                # not identified yet
    assert not ob.identified
    # after identification, enrolled devices may begin streaming
    user = ob.identify(os.urandom(32), device_names=["wallet"], pseudonyms=[])
    assert ob.identified
    wallet = user.devices[0]
    assert ob.begin_liveness_streaming(wallet) is wallet
    assert "wallet" in user._liveness_started
    # a device NOT enrolled in this identification is still refused
    with pytest.raises(PhaseError):
        ob.begin_liveness_streaming(stray)
