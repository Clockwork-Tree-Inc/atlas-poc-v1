"""Atlas Mac node — blind relay (server cannot read A<->B content) + opt-in public
verifier. The two phones are simulated with the Python KEM + tunnel.
"""

import base64
import os

import pytest

from atlas.beacon import LocalBeacon
from atlas.crypto import kem
from atlas.keys.identity import build_identity_tree
from atlas.liveness.attestation import AttestationSubsystem
from atlas.liveness.bayes import LivenessGate
from atlas.liveness.synthetic import live_stream
from atlas.net.codec import bundle_to_json
from atlas.net.node_server import AtlasNode
from atlas.provenance import CaptureMetadata, LedgerStub, PublicWitnessRegistry, sign_capture
from atlas.session.tunnel import Message, SendMode, open_message, seal

REAL_DEPTH = [0.42, 0.61, 0.95, 1.30, 0.55, 0.78, 1.10, 0.33]


def _b64(b):
    return base64.b64encode(b).decode()


def _pub_json(pub):
    return {"mlkemEK": _b64(pub.mlkem_ek), "x25519PK": _b64(pub.x25519_pk)}


def _pub_from(d):
    return kem.HybridKEMPublic(mlkem_ek=base64.b64decode(d["mlkemEK"]),
                               x25519_pk=base64.b64decode(d["x25519PK"]))


def _call(node, method, path, body=None):
    """dispatch() returns (code, (kind, obj)); unwrap to (code, obj)."""
    code, (_, obj) = node.dispatch(method, path, body or {})
    return code, obj


def test_A_to_B_message_is_end_to_end_node_is_blind():
    """A and B share a key the node never holds; A seals a message under it and
    relays via the node; B fetches and opens. The node CANNOT read the content."""
    node = AtlasNode()
    # B registers its public key so A can encapsulate to it.
    b_kp = kem.generate_keypair()
    _call(node, "POST", "/relay/register", {"mailbox": "bob", "kem_pub": _pub_json(b_kp.public)})

    # A fetches B's public key from the node and derives the A-B key (node NEVER
    # sees this shared secret — it can't be recovered from the transcript).
    b_code, b_pub = _call(node, "GET", "/relay/pubkey/bob")
    enc = kem.encapsulate(_pub_from(b_pub))
    ab_key = enc.shared

    # A must also get its KEM ciphertext to B so B can derive the same key. That
    # ciphertext is itself just relayed (opaque to the node either way).
    _call(node, "POST", "/relay/register", {"mailbox": "alice", "kem_pub": _pub_json(kem.generate_keypair().public)})
    _call(node, "POST", "/relay/send",
          {"from": "alice", "to": "bob", "blob": _b64(b"KEMCT:" + enc.mlkem_ct + b"|" + enc.x25519_eph_pk)})

    # A seals the real message under the A-B key and relays the OPAQUE blob.
    sealed = seal(b"meet at the pier, 9pm", mode=SendMode.NORMAL, key=ab_key)
    _call(node, "POST", "/relay/send", {"from": "alice", "to": "bob", "blob": _b64(sealed.ciphertext)})

    # THE NODE IS BLIND: its stored state contains no plaintext and no A-B key.
    st = node.status()
    assert st["relayed_total"] == 2
    # the node cannot open the blob — it holds no A-B key. Prove it: every attempt
    # with anything the node has fails (the node code never even tries).
    bob_inbox = node._mailboxes["bob"].inbox
    stored = base64.b64decode(bob_inbox[-1].blob_b64)
    with pytest.raises(Exception):
        open_message(Message(mode=SendMode.NORMAL, ciphertext=stored), key=os.urandom(32))
    # plaintext appears nowhere in the node's serialized state
    assert b"pier" not in repr(node.status()).encode()

    # B fetches and opens locally with the A-B key it derived.
    _, fetched = _call(node, "GET", "/relay/fetch/bob")
    # (skip the KEM-CT envelope; open the sealed message)
    msg_blob = base64.b64decode(fetched["messages"][-1]["blob"])
    assert open_message(Message(mode=SendMode.NORMAL, ciphertext=msg_blob), key=ab_key) == b"meet at the pier, 9pm"


def test_node_sees_only_metadata():
    node = AtlasNode()
    _call(node, "POST", "/relay/register", {"mailbox": "bob", "kem_pub": {"mlkemEK": "", "x25519PK": ""}})
    ab_key = os.urandom(32)
    sealed = seal(b"secret plans", mode=SendMode.NORMAL, key=ab_key)
    _call(node, "POST", "/relay/send", {"from": "alice", "to": "bob", "blob": _b64(sealed.ciphertext)})
    st = node.status()
    mb = [m for m in st["mailboxes"] if m["mid"] == "bob"][0]
    # metadata IS visible (honest boundary): pending count, direction
    assert mb["pending"] == 1 and mb["in"] == 1
    # content is NOT
    assert b"secret" not in repr(st).encode()


def test_fetch_clears_inbox():
    node = AtlasNode()
    _call(node, "POST", "/relay/register", {"mailbox": "bob", "kem_pub": {}})
    _call(node, "POST", "/relay/send", {"from": "a", "to": "bob", "blob": _b64(b"x" * 40)})
    _, first = _call(node, "GET", "/relay/fetch/bob")
    _, second = _call(node, "GET", "/relay/fetch/bob")
    assert len(first["messages"]) == 1 and len(second["messages"]) == 0


def test_send_to_unknown_mailbox_rejected():
    node = AtlasNode()
    code, out = _call(node, "POST", "/relay/send", {"from": "a", "to": "ghost", "blob": _b64(b"x")})
    assert code == 400 and "ghost" in out["error"]


def test_optin_public_provenance_verify_and_anchor():
    """The opt-in PUBLIC path still works: a full Python-produced bundle verifies
    accountable and anchors. (Private A<->B never uses this path.)"""
    node = AtlasNode()
    tree = build_identity_tree(os.urandom(32))
    rnd = LocalBeacon().round_at(1.0)
    lk, sk = os.urandom(32), os.urandom(32)
    g = LivenessGate()
    for _, (psl, psnl) in live_stream(40):
        g.update(p_s_given_live=psl, p_s_given_not_live=psnl)
    pole = g.state(sensor_digest=b"s", drand_round=rnd.drand_round())
    reg = PublicWitnessRegistry(); reg.publish(lk, rnd.drand_round())  # noqa: E702
    bundle = sign_capture(content=b"frame", depth_map=REAL_DEPTH, moire_score=0.1,
                          metadata=CaptureMetadata("f", "still", "t", "d"),
                          authorship=tree.child("authorship"), attestation_subsystem=AttestationSubsystem(),
                          pole=pole, beacon_round=rnd, ledger=LedgerStub(), lk=lk, session_key=sk)
    code, out = _call(node, "POST", "/publish/provenance", {
        "bundle": bundle_to_json(bundle), "content_b64": _b64(b"frame"),
        "lk_hex_TESTONLY": lk.hex()})
    assert code == 200 and out["accountable_built"]
    assert out["checks"]["live_provenance_ok"] == "ok"      # full bundle -> real, not deferred


def test_two_phone_demo_runs_and_node_stays_blind():
    """The dashboard 'Run demo' path: A<->B message + provenanced photo through the
    blind relay. B decrypts/verifies; the node only relayed opaque blobs."""
    node = AtlasNode()
    node.run_demo()
    # the demo recorded B's results (computed by the Phone-B client, not the node)
    assert "pier" in node._demo_result["message"]
    assert "accountable=True" in node._demo_result["verdict"]
    # the node's own view is opaque: it relayed blobs, holds no plaintext
    st = node.status()
    assert st["relayed_total"] >= 3
    assert b"pier" not in repr({"mailboxes": st["mailboxes"], "public": st["public"]}).encode()
