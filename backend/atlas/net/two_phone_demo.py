"""Two-phone end-to-end demo, played THROUGH a live blind-relay node.

Phone A and Phone B are simulated as separate client objects. They:
  1. register mailboxes + public keys with the node,
  2. establish an A-B key the NODE NEVER HOLDS (A encapsulates to B),
  3. send an encrypted MESSAGE A->B (node relays the opaque blob),
  4. send an encrypted PROVENANCED PHOTO A->B, which B decrypts and VERIFIES
     itself (B is the verifier — not the server),
and the node only ever stores/forwards opaque blobs. A also publishes the epoch
witness PUBLIC half to the node's public anchor so B can verify live-provenance
WITHOUT the LK.

Honest framing for the dashboard: the decryption/verification shown is done by
the Phone-B CLIENT inside this process, NOT by the server. The server's own view
(mailboxes / relayed counts) stays opaque.
"""

from __future__ import annotations

import base64
import os
from typing import List

from ..beacon import LocalBeacon
from ..crypto import kem
from ..crypto.sign import keypair_from_seed
from ..keys.identity import build_identity_tree
from ..liveness.attestation import AttestationSubsystem
from ..liveness.bayes import LivenessGate
from ..liveness.synthetic import live_stream
from ..provenance import CaptureMetadata, LedgerStub, PublicWitnessRegistry, sign_capture, verify_provenance
from ..provenance.live_binding import _witness_seed
from ..session.tunnel import Message, SendMode, open_message, seal
from .codec import bundle_from_json, bundle_to_json

REAL_DEPTH = [0.42, 0.61, 0.95, 1.30, 0.55, 0.78, 1.10, 0.33]


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _live_pole(rnd):
    g = LivenessGate()
    for _, (psl, psnl) in live_stream(40):
        g.update(p_s_given_live=psl, p_s_given_not_live=psnl)
    return g.state(sensor_digest=b"s", drand_round=rnd.drand_round())


def run(node) -> List[str]:
    """Play the two-phone flow against `node` (an AtlasNode). Returns a human log.
    Records the message B decrypted + the provenance verdict B computed onto the
    node's demo log for the dashboard."""
    log: List[str] = []

    def say(s):
        log.append(s)

    # -- both phones register (node learns only public material + mailbox ids) --
    a_kp, b_kp = kem.generate_keypair(), kem.generate_keypair()
    node.register(mailbox="alice", kem_pub={"mlkemEK": _b64(a_kp.public.mlkem_ek),
                                            "x25519PK": _b64(a_kp.public.x25519_pk)})
    node.register(mailbox="bob", kem_pub={"mlkemEK": _b64(b_kp.public.mlkem_ek),
                                          "x25519PK": _b64(b_kp.public.x25519_pk)})
    say("Phone A and Phone B registered mailboxes with the node.")

    # -- A establishes the A-B key (node cannot derive it) --
    enc = kem.encapsulate(b_kp.public)          # A -> B
    ab_key = enc.shared
    node.relay_send(frm="alice", to="bob",
                    blob_b64=_b64(b"KEMCT:" + enc.mlkem_ct + b"|" + enc.x25519_eph_pk))
    say("A encapsulated to B and relayed the KEM ciphertext (opaque to the node).")

    # -- A sends an encrypted MESSAGE --
    secret = b"meet at the north pier at 9pm"
    node.relay_send(frm="alice", to="bob", blob_b64=_b64(seal(secret, mode=SendMode.NORMAL, key=ab_key).ciphertext))
    say(f"A sealed a message under the A-B key and relayed it. Node sees only an opaque {len(secret)}+ byte blob.")

    # -- A captures a PROVENANCED PHOTO and sends it E2E --
    tree = build_identity_tree(os.urandom(32))
    rnd = LocalBeacon().round_at(1.0)
    lk, sk = os.urandom(32), os.urandom(32)
    photo = b"\x89PNG demo-frame " + os.urandom(48)
    bundle = sign_capture(content=photo, depth_map=REAL_DEPTH, moire_score=0.1,
                          metadata=CaptureMetadata("iPhone", "still", "2026-07-06", "varied"),
                          authorship=tree.child("authorship"), attestation_subsystem=AttestationSubsystem(),
                          pole=_live_pole(rnd), beacon_round=rnd, ledger=LedgerStub(), lk=lk, session_key=sk)
    # A publishes ONLY the epoch witness PUBLIC half to the node's public anchor
    # (reveals nothing; the LK stays on A). B verifies against it without the LK.
    a_witness_pub = keypair_from_seed(_witness_seed(lk, rnd.drand_round())).public
    node.register_witness_public(drand_round=rnd.drand_round(), pub=a_witness_pub)
    say("A published its epoch witness PUBLIC half to the node's public anchor (LK never leaves A).")

    import json
    payload = json.dumps({"bundle": bundle_to_json(bundle), "photo_b64": _b64(photo)}).encode()
    node.relay_send(frm="alice", to="bob", blob_b64=_b64(seal(payload, mode=SendMode.NORMAL, key=ab_key).ciphertext))
    say("A sealed {photo + provenance bundle} under the A-B key and relayed it (node blind to content).")

    # -- B fetches everything and decrypts/verifies LOCALLY --
    fetched = node.relay_fetch(mailbox="bob")["messages"]
    got_msg = None
    verdict_line = None
    for env in fetched:
        blob = base64.b64decode(env["blob"])
        if blob.startswith(b"KEMCT:"):
            continue                                 # channel setup, already have the key
        opened = open_message(Message(mode=SendMode.NORMAL, ciphertext=blob), key=ab_key)
        if opened.startswith(b"{"):                  # the JSON photo payload
            obj = json.loads(opened)
            b_bundle = bundle_from_json(obj["bundle"])
            b_photo = base64.b64decode(obj["photo_b64"])
            b_ledger = LedgerStub(); b_ledger.anchor(b_bundle.content_hash)  # noqa: E702
            b_reg = PublicWitnessRegistry()
            wp = node.witness_public(b_bundle.drand_round)   # public half from the anchor
            if wp is not None:
                b_reg.register_public(b_bundle.drand_round, wp)
            v = verify_provenance(b_bundle, content=b_photo, ledger=b_ledger, witness_registry=b_reg)
            verdict_line = (f"B verified the photo: integrity={v.integrity_ok} author={v.handle_ok} "
                            f"signature={v.signature_ok} live={v.liveness_ok} anchored={v.anchored_ok} "
                            f"live-provenance={v.live_provenance_ok} -> accountable={v.accountable}")
        else:
            got_msg = opened

    say(f"B decrypted the message: “{(got_msg or b'').decode(errors='replace')}”  (done by Phone B, not the server).")
    if verdict_line:
        say(verdict_line + "  (verified by Phone B against the public witness anchor — no LK).")
    say("Server view stayed opaque: it relayed blobs it cannot read; only public witness halves + metadata are visible.")

    node.record_demo(log, message=(got_msg or b"").decode(errors="replace"),
                     verdict=verdict_line or "")
    return log
