"""The node is wired as the LKG aggregator AND as the inheritance custodian.

  * /beacon serves the aggregator's signed QRNG EPOCH beacon (source "atlas-epoch-beacon", NOT
    drand); the signature verifies against the served aggregator key, and the key is STABLE across a
    restart (persisted seed). Works offline — external drand is only the optional anchor.
  * /inherit/{arm,trigger,serve,status} drive the gate end-to-end: armed won't serve, a triggered
    gate past its window serves the heir blob, and a veto with a forged (non-drand) beacon signature
    is rejected fail-closed.
"""
import base64

import pytest

from atlas.beacon import EpochBeaconService, verify_epoch_round
from atlas.beacon.epoch import EpochRound
from atlas.crypto.sign import HybridSigPublic, generate_sig_keypair, sign
from atlas.keys.inheritance import trigger_message, veto_message
from atlas.net.node_server import AtlasNode


@pytest.fixture(autouse=True)
def _storage(tmp_path, monkeypatch):
    monkeypatch.setenv("ATLAS_STORAGE", str(tmp_path))


def _node(tmp_path, **kw):
    """A relay wired to an in-process Atlas aggregator (persisted under tmp_path) — mirrors a relay
    consuming the remote Atlas epoch service."""
    svc = EpochBeaconService(storage_dir=str(tmp_path / "aggregator"))
    return AtlasNode(epoch_service=svc, **kw)


def _round_from(out) -> EpochRound:
    return EpochRound(epoch=out["epoch"], randomness=bytes.fromhex(out["randomness"]),
                      anchor=bytes.fromhex(out["anchor"]), signature=bytes.fromhex(out["signature"]))


def test_beacon_serves_signed_epoch_not_drand(tmp_path):
    node = _node(tmp_path)
    out = node.beacon_now()
    assert out["source"] == "atlas-epoch-beacon"       # the epoch key is the QRNG epoch, NOT drand
    assert out["verified"] and out["epoch"] >= 1
    pub = HybridSigPublic.decode(bytes.fromhex(out["aggregator_pub"]))
    assert verify_epoch_round(_round_from(out), pub)   # the aggregator's signature verifies
    # external drand is the OPTIONAL defence-in-depth anchor: absent (None) when the relay is
    # unreachable, an int round when reachable — either way the epoch fires and the value is clean.
    assert out["anchor_drand_round"] is None or isinstance(out["anchor_drand_round"], int)


def test_bare_relay_without_aggregator_falls_back_to_drand_bootstrap():
    # A relay with NO Atlas epoch service configured does NOT run an aggregator — it bootstraps on
    # drand (or reports unavailable if drand is unreachable), never fabricating an epoch key.
    out = AtlasNode().beacon_now()
    assert out.get("source") == "drand-bootstrap" or out.get("verified") is False
    assert "aggregator_pub" not in out                 # the blind relay holds no aggregator key


def test_aggregator_key_stable_across_restart(tmp_path):
    d = str(tmp_path / "aggregator")
    k1 = EpochBeaconService(storage_dir=d).public.encode()
    k2 = EpochBeaconService(storage_dir=d).public.encode()   # a "restart" on the same storage
    assert k1 == k2                                          # persisted seed → same aggregator identity


def _arm(node, owner, lawyer, *, window=10, loc="abc123"):
    return node.dispatch("POST", "/inherit/arm", {
        "locator": loc, "heir_blob": base64.b64encode(b"opaque-heir-share").decode(),
        "gate_id": (b"gate-id-0123456789ab").hex(),
        "owner_pub": base64.b64encode(owner.public.encode()).decode(),
        "trigger_pub": base64.b64encode(lawyer.public.encode()).decode(),
        "veto_window_rounds": window})


def test_inheritance_endpoints_end_to_end():
    node = AtlasNode()
    owner, lawyer = generate_sig_keypair(), generate_sig_keypair()
    gid = b"gate-id-0123456789ab"

    code, (_, arm) = _arm(node, owner, lawyer)
    assert code == 200 and arm["status"] == "armed"

    # armed → serve is refused (fail-closed, 400)
    code, (_, err) = node.dispatch("GET", "/inherit/serve/abc123", {})
    assert code == 400

    # the attorney fires a death-trigger at an early round; the node's drand clock is far past it,
    # so the window has elapsed and the heir blob becomes releasable.
    sig = base64.b64encode(sign(lawyer, trigger_message(gid, 100))).decode()
    code, (_, tr) = node.dispatch("POST", "/inherit/trigger",
                                  {"locator": "abc123", "at_round": 100, "signature": sig})
    assert code == 200
    code, (_, served) = node.dispatch("GET", "/inherit/serve/abc123", {})
    assert code == 200
    assert base64.b64decode(served["heir_blob"]) == b"opaque-heir-share"


def test_forged_veto_beacon_sig_is_rejected():
    node = AtlasNode()
    owner, lawyer = generate_sig_keypair(), generate_sig_keypair()
    gid = b"gate-id-0123456789ab"
    _arm(node, owner, lawyer, loc="dd11")
    node.dispatch("POST", "/inherit/trigger", {
        "locator": "dd11", "at_round": 100,
        "signature": base64.b64encode(sign(lawyer, trigger_message(gid, 100))).decode()})
    # a veto whose beacon_sig is not drand's genuine signature is rejected before it can abort
    code, (_, err) = node.dispatch("POST", "/inherit/veto", {
        "locator": "dd11", "at_round": 105, "beacon_sig": base64.b64encode(b"forged").decode(),
        "signature": base64.b64encode(sign(owner, veto_message(gid, 105, b"forged"))).decode()})
    assert code == 400 and "drand" in err["error"].lower()
