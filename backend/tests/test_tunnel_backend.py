"""Mac PQC tunnel backend — in-process end-to-end (the phone is simulated with the
Python KEM+tunnel, standing in for the Swift AtlasTunnelClient).

This verifies the SERVER logic here: handshake -> derive matching shared secret ->
open a sealed message -> return a sealed ACK. The real Swift<->Python KEM interop
is confirmed on device; the X-Wing combiner order it depends on is pinned by the
`xwing_combine` parity vector.
"""

import base64

import pytest

from atlas.crypto import kem
from atlas.net.tunnel_backend import TunnelBackend
from atlas.session.tunnel import SendMode, open_message, seal, Message


def _b64(b):
    return base64.b64encode(b).decode()


def test_handshake_derives_matching_shared_secret():
    backend = TunnelBackend()
    pk = backend.public_key()
    # "phone" side: encapsulate to the server's published public key.
    recipient = kem.HybridKEMPublic(mlkem_ek=base64.b64decode(pk["mlkemEK"]),
                                    x25519_pk=base64.b64decode(pk["x25519PK"]))
    enc = kem.encapsulate(recipient)
    session = backend.complete(mlkem_ct=enc.mlkem_ct, x25519_eph_pk=enc.x25519_eph_pk)
    # the server must hold the SAME shared secret the phone derived
    assert backend._sessions[session] == enc.shared


def test_full_tunnel_roundtrip_via_dispatch():
    backend = TunnelBackend()
    _, pk = backend.dispatch("GET", "/kem/public-key", {})
    recipient = kem.HybridKEMPublic(mlkem_ek=base64.b64decode(pk["mlkemEK"]),
                                    x25519_pk=base64.b64decode(pk["x25519PK"]))
    enc = kem.encapsulate(recipient)
    _, comp = backend.dispatch("POST", "/kem/complete",
                               {"mlkemCT": _b64(enc.mlkem_ct), "x25519EphPK": _b64(enc.x25519_eph_pk)})
    session = comp["session"]

    # phone seals a message under its shared key (== server's session key)
    msg = seal(b"hello atlas", mode=SendMode.NORMAL, key=enc.shared)
    code, out = backend.dispatch("POST", "/tunnel/message",
                                 {"session": session, "ciphertext": _b64(msg.ciphertext), "mode": "1"})
    assert code == 200
    # the sealed ACK opens under the same key and echoes the plaintext
    ack = Message(mode=SendMode.NORMAL, ciphertext=base64.b64decode(out["ciphertext"]))
    assert open_message(ack, key=enc.shared) == b"ATLAS-ACK:hello atlas"


def test_unknown_session_is_rejected():
    backend = TunnelBackend()
    code, out = backend.dispatch("POST", "/tunnel/message",
                                 {"session": "deadbeef", "ciphertext": _b64(b"\x00" * 40), "mode": "1"})
    assert code == 400 and "session" in out["error"]


def test_wrong_shared_secret_fails_to_open():
    """A phone that derived a DIFFERENT shared secret (e.g. a divergent combiner —
    the bug the xwing_combine vector guards) cannot open the tunnel: the AEAD
    fails, surfaced as a 400."""
    backend = TunnelBackend()
    _, pk = backend.dispatch("GET", "/kem/public-key", {})
    recipient = kem.HybridKEMPublic(mlkem_ek=base64.b64decode(pk["mlkemEK"]),
                                    x25519_pk=base64.b64decode(pk["x25519PK"]))
    enc = kem.encapsulate(recipient)
    _, comp = backend.dispatch("POST", "/kem/complete",
                               {"mlkemCT": _b64(enc.mlkem_ct), "x25519EphPK": _b64(enc.x25519_eph_pk)})
    # seal under a WRONG key (simulating a mismatched combiner) -> server open fails
    wrong = seal(b"x", mode=SendMode.NORMAL, key=b"\x00" * 32)
    code, out = backend.dispatch("POST", "/tunnel/message",
                                 {"session": comp["session"], "ciphertext": _b64(wrong.ciphertext), "mode": "1"})
    assert code == 400
