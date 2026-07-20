"""The relying-party server + wire serialization + the node's /rp endpoints — the
phone-authenticates-to-a-bank loop, end to end."""

import os

from atlas.auth import (
    RelyingPartyServer,
    assertion_from_json,
    assertion_to_json,
    authenticate,
)
from atlas.keys.hardware_key import YubiKeyBio
from atlas.keys.identity import build_identity_tree
from atlas.liveness.bayes import LivenessGate
from atlas.liveness.synthetic import live_stream
from atlas.net.node_server import AtlasNode


def _pole():
    g = LivenessGate()
    for _, (psl, psnl) in live_stream(40):
        g.update(p_s_given_live=psl, p_s_given_not_live=psnl)
    return g.state(sensor_digest=b"s", drand_round=b"\x00" * 8)


def _user():
    return build_identity_tree(os.urandom(32)).child("authorship")


def test_rp_server_login_and_stepup():
    user, yk = _user(), YubiKeyBio()
    bank = RelyingPartyServer("acme-bank")
    bank.register("u", handle=user.handle, public=user.public, step_up_public=yk.public)
    ch = bank.challenge("u", "login")
    assert bank.verify("u", authenticate(ch, authorship=user, pole=_pole()))
    ch2 = bank.challenge("u", "authorize-transfer", require_step_up=True)
    assert bank.verify("u", authenticate(ch2, authorship=user, pole=_pole(), yubikey=yk, fingerprint_matched=True))


def test_challenge_is_one_shot():
    user = _user()
    bank = RelyingPartyServer("acme-bank")
    bank.register("u", handle=user.handle, public=user.public)
    ch = bank.challenge("u", "login")
    a = authenticate(ch, authorship=user, pole=_pole())
    assert bank.verify("u", a)              # first use ok
    assert not bank.verify("u", a)          # replay -> challenge consumed -> rejected


def test_assertion_survives_wire_serialization():
    user = _user()
    bank = RelyingPartyServer("acme-bank")
    bank.register("u", handle=user.handle, public=user.public)
    ch = bank.challenge("u", "login")
    a = authenticate(ch, authorship=user, pole=_pole())
    rewired = assertion_from_json(assertion_to_json(a))    # to JSON and back
    assert bank.verify("u", rewired)


def test_node_rp_endpoints_end_to_end():
    import base64
    from atlas.auth.relying_party import _pub_json
    node = AtlasNode()
    user, yk = _user(), YubiKeyBio()
    # register the authenticator with the node's mock bank
    node.rp_register(user_id="u", handle_b64=base64.b64encode(user.handle).decode(),
                     public=_pub_json(user.public),
                     step_up_public_b64=base64.b64encode(yk.public).decode())
    # bank issues a step-up challenge; phone authenticates; bank verifies
    from atlas.auth import challenge_from_json
    ch = challenge_from_json(node.rp_challenge(user_id="u", action="authorize-transfer", require_step_up=True))
    a = authenticate(ch, authorship=user, pole=_pole(), yubikey=yk, fingerprint_matched=True)
    assert node.rp_verify(user_id="u", assertion=assertion_to_json(a))["approved"] is True
