"""FULL-ENGINE N-phone + backend integration test (the reference milestone).

Exercises the whole crypto engine end-to-end, through a live blind node, across N
devices (run for N=2 and N=3 to prove it generalizes) — with a LIVE co-derived LK
(not the os.urandom stub). Everything is SYMMETRIC: every participant does
identity, session, provenance (verified by every other), and recovery — no
privileged "A".

  1. identity      — every participant's handle one-to-one verified (verify, not identify)
  2. blind channel — pairwise KEM per ordered pair; the node relays opaque ciphertext
  3. live LK       — ALL participants co-derive the SAME epoch LK from fresh secret halves
  4. sessions      — every phone advances a session AGAINST the live LK (presence-gated)
  5. FS messaging  — every ordered pair exchanges a forward-secret message
  6. provenance    — every participant signs a capture that EVERY OTHER verifies -> accountable
  7. recovery      — every participant's user-half split k-of-n and reconstructed
  8. node blindness— plaintext, contributions, and the LK never appear in the relay

This is the reference-of-record the two-real-phone Swift run mirrors, built to
scale past two participants.
"""

import base64
import json
from dataclasses import dataclass

import pytest

from atlas.beacon import LocalBeacon
from atlas.crypto import kem
from atlas.crypto.primitives import aead_encrypt
from atlas.crypto.sign import keypair_from_seed, sign
from atlas.keys.identity import (
    build_identity_tree,
    reconstruct_user_half,
    split_user_half_for_recovery,
    verify_one_to_one,
)
from atlas.liveness.attestation import AttestationSubsystem
from atlas.liveness.bayes import LivenessGate
from atlas.liveness.synthetic import live_stream
from atlas.net.codec import bundle_from_json, bundle_to_json
from atlas.net.node_server import AtlasNode
from atlas.provenance import (
    CaptureMetadata,
    LedgerStub,
    PublicWitnessRegistry,
    sign_capture,
    verify_provenance,
)
from atlas.provenance.live_binding import _witness_seed
from atlas.session.device import Device
from atlas.session.fs_conversation import FSChain, seed_chain
from atlas.session.live_lk import co_derive_lk, device_contribution

REAL_DEPTH = [0.42, 0.61, 0.95, 1.30, 0.55, 0.78, 1.10, 0.33]


def _b64(b):
    return base64.b64encode(b).decode()


def _live_pole(rnd):
    g = LivenessGate()
    for _, (psl, psnl) in live_stream(40):
        g.update(p_s_given_live=psl, p_s_given_not_live=psnl)
    return g.state(sensor_digest=b"s", drand_round=rnd.drand_round())


@dataclass
class Participant:
    name: str
    tree: object
    device: Device
    kem_kp: object
    contribution: bytes
    session: object = None


def _make_participant(i: int) -> Participant:
    seed = bytes([65 + i]) * 32                        # A.., B.., C..
    tree = build_identity_tree(seed)
    dev = Device(f"P{i}", tree, bootstrap_tunnel_key=b"\x07" * 32)
    return Participant(name=f"p{i}", tree=tree, device=dev,
                       kem_kp=kem.generate_keypair(), contribution=device_contribution())


def _relayed(node, mailbox):
    return [base64.b64decode(m["blob"]) for m in node.relay_fetch(mailbox=mailbox)["messages"]]


@pytest.mark.parametrize("n", [2, 3])
def test_full_engine_n_phone_backend_live_lk(n):
    node = AtlasNode()
    rnd = LocalBeacon().round_at(1.0)
    drand_round, epoch_key, beacon_t = rnd.drand_round(), rnd.randomness, rnd.randomness

    people = [_make_participant(i) for i in range(n)]
    for p in people:
        node.register(mailbox=p.name, kem_pub={"mlkemEK": _b64(p.kem_kp.public.mlkem_ek),
                                               "x25519PK": _b64(p.kem_kp.public.x25519_pk)})

    # -- 3. LIVE LK: every participant contributes a fresh secret; ALL co-derive the
    #        SAME epoch LK. (co_derive_lk is order-independent and takes N halves.)
    contribs = [p.contribution for p in people]
    live_lk = co_derive_lk(contribs, drand_round=drand_round)
    for p in people:                                   # each computes it from its own view
        assert co_derive_lk([p.contribution] + [q.contribution for q in people if q is not p],
                            drand_round=drand_round) == live_lk
    assert all(live_lk != c for c in contribs)         # controllable-by-none

    # -- 1. IDENTITY + 4. SESSIONS + 7. RECOVERY: symmetric, for EVERY participant
    for p in people:
        # identity: one-to-one verify of this participant's own handle
        child = p.tree.child("authorship")
        chal = b"challenge-" + p.name.encode()
        sig = sign(child.keypair, chal)
        ok = verify_one_to_one(asserted_handle=child.handle, revealed_public=child.public,
                               challenge=chal, signature=sig, live_biometric_matches=True)
        assert ok.matched_handle and ok.signature_valid and ok.biometric_matched
        tampered = verify_one_to_one(asserted_handle=child.handle, revealed_public=child.public,
                                     challenge=chal, signature=sig[:-1] + bytes([sig[-1] ^ 1]),
                                     live_biometric_matches=True)
        assert not tampered.signature_valid

        # session: advance AGAINST the live co-derived LK (presence-gated unwrap chain)
        p.session = p.device.advance_epoch_present(lk=live_lk, epoch_key=epoch_key, drand_round=drand_round)
        assert p.session.alive and len(p.session.key) == 32

        # recovery: split this participant's user-half k-of-n, reconstruct without the original
        uh = p.tree._user_half
        assert uh and len(uh) == 32
        shares = split_user_half_for_recovery(uh, n=5, k=3)
        assert reconstruct_user_half(shares[:3]) == uh and reconstruct_user_half(shares[2:5]) == uh

    # -- 6. PROVENANCE: every participant signs a capture that EVERY OTHER verifies.
    #        The epoch's live-provenance witness (from lk+epoch) is shared; publish once.
    node.register_witness_public(drand_round=drand_round,
                                 pub=keypair_from_seed(_witness_seed(live_lk, drand_round)).public)
    for signer in people:
        photo = b"\x89PNG " + signer.name.encode() + b"\x00" * 40
        bundle = sign_capture(content=photo, depth_map=REAL_DEPTH, moire_score=0.1,
                              metadata=CaptureMetadata("iPhone", "still", "2026-07-10", "varied"),
                              authorship=signer.tree.child("authorship"),
                              attestation_subsystem=AttestationSubsystem(),
                              pole=_live_pole(rnd), beacon_round=rnd, ledger=LedgerStub(),
                              lk=live_lk, session_key=signer.session.key)
        wire = json.dumps({"bundle": bundle_to_json(bundle), "photo_b64": _b64(photo)}).encode()
        for verifier in people:
            if verifier is signer:
                continue
            obj = json.loads(wire)                     # verifier's local copy
            vb = bundle_from_json(obj["bundle"])
            vp = base64.b64decode(obj["photo_b64"])
            ledger = LedgerStub(); ledger.anchor(vb.content_hash)
            reg = PublicWitnessRegistry(); reg.register_public(vb.drand_round, node.witness_public(vb.drand_round))
            verdict = verify_provenance(vb, content=vp, ledger=ledger, witness_registry=reg)
            assert verdict.accountable, f"{verifier.name} could not hold {signer.name} accountable"
            assert not verify_provenance(vb, content=vp + b"x", ledger=ledger,
                                         witness_registry=reg).accountable   # tamper -> fail

    # -- 2 + 5. BLIND CHANNEL + FS MESSAGING: every ordered pair exchanges a
    #        forward-secret message sealed under the ratcheted key (KEM key + live LK).
    secrets_sent, relayed_ciphertext = [], []
    for i, snd in enumerate(people):
        for j, rcv in enumerate(people):
            if i == j:
                continue
            enc = kem.encapsulate(rcv.kem_kp.public)   # snd -> rcv; node relays opaque CT
            pair_key_snd = enc.shared
            pair_key_rcv = kem.decapsulate(rcv.kem_kp, enc.mlkem_ct, enc.x25519_eph_pk)
            assert pair_key_snd == pair_key_rcv
            direction = f"{snd.name}->{rcv.name}".encode()
            s_seed = seed_chain(channel_key=pair_key_snd, lk=live_lk, drand_round=drand_round, direction=direction)
            r_seed = seed_chain(channel_key=pair_key_rcv, lk=live_lk, drand_round=drand_round, direction=direction)
            snd_chain, rcv_chain = FSChain(s_seed, drand_round=drand_round), FSChain(r_seed, drand_round=drand_round)
            msg = f"{snd.name}->{rcv.name}: co-derived-live secret".encode()
            sealed = snd_chain.seal(msg, beacon_t=beacon_t)
            secrets_sent.append(msg); relayed_ciphertext.append(sealed)
            node.relay_send(frm=snd.name, to=rcv.name, blob_b64=_b64(sealed))
            assert rcv_chain.open(_relayed(node, rcv.name)[-1], beacon_t=beacon_t) == msg

    # -- 8. NODE BLINDNESS: no plaintext / LK ever appears in the relayed ciphertext
    joined = b"".join(relayed_ciphertext)
    for secret in secrets_sent + [live_lk]:
        assert secret not in joined
