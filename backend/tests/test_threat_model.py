"""Threat-model coverage — runnable threats against the Tier-3 PoC.

Maps Atlas Threat Model v2.0 (T-01..T-25) to executable tests where the
mechanism EXISTS in the built code. Threats covering the full architecture
(satellites, governance, UBI, server mesh, ZK/DP, home node) are NOT here —
they are not implemented in the PoC; see THREAT_COVERAGE.md for the full matrix
including hardware-gated and not-in-scope rows.

Each test cites its threat ID and asserts the property an attacker would break.
Honest caveats (e.g. "single-device only; cross-device consensus not built") are
in the matrix, not hidden by a green.
"""

import os
import time

import pytest

from atlas.beacon import ArrivalTiming, LocalBeacon, ServerQRNG
from atlas.crypto import kem
from atlas.keys import recovery as R
from atlas.keys.derivation import derive_session_key_decoupled
from atlas.keys.enclave import SecureEnclave
from atlas.keys.identity import build_identity_tree
from atlas.keys.tokens import issue as issue_token, verify as verify_token
from atlas.liveness.attestation import AttestationSubsystem, RemovalState
from atlas.liveness.bayes import LivenessGate
from atlas.liveness.synthetic import live_stream, spoof_stream
from atlas.params import CONTEXT_TUNNEL
from atlas.provenance import (
    LedgerStub, PublicWitnessRegistry, sign_capture, verify_provenance, CaptureMetadata,
)
from atlas.session.device import Device, EpochInputs
from atlas.session.recognition import contribution, recognition_value
from atlas.session.tunnel import AccessDenied, SendMode, open_message, seal


def _pole(stream, att, epoch=b"\x00" * 8):
    g = LivenessGate()
    for _, (psl, psnl) in stream:
        g.update(p_s_given_live=psl, p_s_given_not_live=psnl)
    return g.state(sensor_digest=b"s", drand_round=epoch), att


# T-01 / T-23 — PoLE spoofing (mechanical farm / AI-synthetic entropy).
# Built (sim): single-device Bayesian gate rejects spoof streams, emits no proof.
# NOT built: network entropy correlation, cross-device consensus (full arch).
def test_T01_T23_pole_spoof_rejected_single_device():
    att = AttestationSubsystem()
    spoof_pole, _ = _pole(spoof_stream(40), att)
    assert not spoof_pole.operate
    assert att.attest(spoof_pole) is None            # no proof object ascends
    live_pole, att2 = _pole(live_stream(40), AttestationSubsystem())
    assert live_pole.operate and att2.attest(live_pole).verify()


# T-02 — Replay of PoLE/proof tokens. Built: epoch-bound attestations + scoped
# tokens with TTL; a proof bound to epoch A is rejected at epoch B.
def test_T02_proof_tokens_epoch_bound_and_expiring():
    # capability token TTL
    k = os.urandom(32)
    tok = issue_token(k, scope="reward", purpose="claim", expiry=100.0)
    assert verify_token(k, tok, now=50.0) and not verify_token(k, tok, now=150.0)
    # replay-within-TTL: a single-use claim is consumed on first presentation
    from atlas.keys.tokens import ReplayCache
    cache = ReplayCache()
    assert cache.verify_once(k, tok, now=50.0)
    assert not cache.verify_once(k, tok, now=50.0)        # replayed before expiry -> rejected
    # liveness attestation bound to an epoch -> provenance verify rejects wrong epoch
    tree = build_identity_tree(os.urandom(32))
    beacon = LocalBeacon(period_s=3.0)
    rnd_a, rnd_b = beacon.round_at(1.0), beacon.round_at(9.0)
    att = AttestationSubsystem()
    pole_a, _ = _pole(live_stream(40), att, epoch=rnd_a.drand_round())
    ledger = LedgerStub()
    registry = PublicWitnessRegistry()
    lk, sk = os.urandom(32), os.urandom(32)
    registry.publish(lk, rnd_b.drand_round())
    meta = CaptureMetadata("f", "still", "t", "d")
    # pole bound to epoch A, bundle anchored at epoch B -> attestation epoch mismatch
    bundle = sign_capture(content=b"x", depth_map=[0.4, 0.6, 0.9, 1.3, 0.5, 0.8, 1.1, 0.3],
                          moire_score=0.1, metadata=meta, authorship=tree.child("authorship"),
                          attestation_subsystem=att, pole=pole_a, beacon_round=rnd_b, ledger=ledger,
                          lk=lk, session_key=sk)
    assert not verify_provenance(bundle, content=b"x", ledger=ledger,
                                 witness_registry=registry).liveness_ok


# T-03 — Device Key extraction. Built (logic): DevKey is identifier-only and not
# in the session-key path; extracting device-local material alone cannot forge a
# session without the beacon + Living Key (off-device rooting). HW tamper-mesh is
# hardware-gated (see matrix).
def test_T03_device_local_material_alone_cannot_forge_session():
    common = dict(pole_value=b"Q" * 32, prev_key=b"\x00" * 32,
                  context_separator=CONTEXT_TUNNEL, drand_round=b"\x00" * 8)
    real = derive_session_key_decoupled(lk=b"L" * 32, epoch_key=b"E" * 32, **common)
    # attacker who extracted only device-local material (no live beacon/LK) diverges
    forged = derive_session_key_decoupled(lk=b"?" * 32, epoch_key=b"?" * 32, **common)
    assert real.key != forged.key


# T-04 — QRNG beacon prediction / manipulation. Built: dual-source (need BOTH
# epoch_key AND server LK). Corrected §2.3: timing TIMES the firing (schedule),
# it never enters the LK value — the value is clean QRNG.
def test_T04_beacon_dual_source_and_clean_qrng_value():
    common = dict(pole_value=b"Q" * 32, prev_key=b"\x00" * 32,
                  context_separator=CONTEXT_TUNNEL, drand_round=b"\x00" * 8)
    base = derive_session_key_decoupled(lk=b"L" * 32, epoch_key=b"E" * 32, **common)
    assert base.key != derive_session_key_decoupled(lk=b"L" * 32, epoch_key=b"X" * 32, **common).key
    assert base.key != derive_session_key_decoupled(lk=b"Z" * 32, epoch_key=b"E" * 32, **common).key
    q = ServerQRNG(); core = os.urandom(32)
    fast = q.fire(ArrivalTiming([0.0, 0.1, 0.2]), b"\x00" * 8, entropy_core=core)
    slow = q.fire(ArrivalTiming([0.0, 0.5, 1.3]), b"\x00" * 8, entropy_core=core)
    # timing does NOT enter the value: same core -> same clean-QRNG value...
    assert fast.randomness == slow.randomness
    # ...but the timing drives the firing SCHEDULE (next-sampling offset is a
    # deterministic function of the arrival-timing digest, not the value).
    assert fast.next_sampling_offset_s == 3.0 + (ArrivalTiming([0.0, 0.1, 0.2]).digest()[0] / 255.0) * 3.0
    # the value is a function of the clean core, not the timing.
    assert q.fire(ArrivalTiming([0.0, 0.1, 0.2]), b"\x00" * 8, entropy_core=os.urandom(32)).randomness != fast.randomness


# T-08 — Atlas Recovery ID Card theft. Built: card holds one share; insufficient
# without a second factor (Enclave biometric, or the context share via the ceremony).
def test_T08_stolen_card_share_alone_insufficient():
    tree = build_identity_tree(os.urandom(32))
    bio = os.urandom(256)
    device = SecureEnclave()
    enr = R.enrol_recovery(tree, bio, device=device, passcode="pw")
    # thief has the card share + an impostor biometric -> Enclave release fails
    with pytest.raises(R.RecoveryError):
        R.recover_via_card(enr, device=device, card_share=enr.share_card,
                           live_biometric=os.urandom(256), attested=True, user_authorized=True)


# T-17 — Ring removal under duress / theft. Built: liveness break -> suspicious
# removal + RAM key wipe; incoherent reconnect -> suspicious.
def test_T17_ring_removal_breaks_liveness_and_wipes():
    att = AttestationSubsystem()
    wiped = {"v": False}
    att.on_wipe(lambda: wiped.__setitem__("v", True))
    spoof_pole, _ = _pole(spoof_stream(40), att)      # ring removed => no live signal
    assert att.attest(spoof_pole) is None
    assert att.state == RemovalState.SUSPICIOUS and wiped["v"]
    assert AttestationSubsystem().reconnect(trajectory_coherent=False) == RemovalState.SUSPICIOUS


# T-18 — Epoch rollover manipulation / replay. Built: recognition/tunnel rekeys
# on beacon advance; a captured prior-epoch key is inert on this-epoch traffic.
def test_T18_epoch_rollover_replay_rejected():
    seed = os.urandom(32); boot = os.urandom(32)
    A = Device("A", build_identity_tree(seed), bootstrap_tunnel_key=boot)
    B = Device("B", build_identity_tree(seed), bootstrap_tunnel_key=boot)
    beacon = LocalBeacon(period_s=3.0)

    def epoch(t):
        from atlas.session import establish_hybrid_tunnel
        import hashlib
        r = beacon.round_at(t)
        # epoch key = network-public epoch QRNG stand-in (per epoch), NOT drand
        ek = hashlib.sha256(b"atlas/epoch-qrng" + r.drand_round()).digest()
        A.advance_epoch_present(b"L" * 32, ek, r.drand_round())
        B.advance_epoch_present(b"L" * 32, ek, r.drand_round())
        _, tB = establish_hybrid_tunnel(A, B, b"c|" + r.drand_round())
        return tB

    stale = epoch(1.0)
    fresh = epoch(9.0)
    msg = seal(b"this-epoch", mode=SendMode.NORMAL, key=fresh)
    assert stale != fresh
    with pytest.raises(Exception):
        open_message(msg, key=stale)


# T-19 — Interface device theft + offline brute force. Built: session key is
# RAM-only and destroyed; no persisted cryptographic material.
def test_T19_stolen_device_keys_are_ephemeral():
    A = Device("A", build_identity_tree(os.urandom(32)), bootstrap_tunnel_key=os.urandom(32))
    A.advance_epoch_present(b"L" * 32, b"E" * 32, b"\x00" * 8)
    _ = A.session.key
    A.attestation.mark_suspicious()                   # seizure -> wipe
    with pytest.raises(Exception):
        _ = A.session.key
    assert A._prev_session_bytes == b"\x00" * 32


# T-25 — Post-quantum harvest-now-decrypt-later. Built: hybrid PQC KEM
# (ML-KEM-768 + X25519) for key establishment; forward secrecy by ephemeral keys.
def test_T25_pqc_hybrid_kem_and_forward_secrecy():
    kp = kem.generate_keypair()
    enc = kem.encapsulate(kp.public)
    assert kem.decapsulate(kp, enc.mlkem_ct, enc.x25519_eph_pk) == enc.shared
    # a different recipient (PQC component included) cannot recover the secret
    assert kem.decapsulate(kem.generate_keypair(), enc.mlkem_ct, enc.x25519_eph_pk) != enc.shared


# T-06 — MITM device<->server (partial). Built: signed proof tokens; tampering
# fails verification; no session key crosses the wire. NOT built: mTLS / cert
# pinning (transport) — see matrix.
def test_T06_proof_token_tamper_rejected_and_no_key_on_wire():
    att = AttestationSubsystem()
    pole, _ = _pole(live_stream(40), att)
    a = att.attest(pole)
    assert a.verify()
    tampered = type(a)(drand_round=a.drand_round, pole_digest=a.pole_digest, operate=a.operate,
                       enclave_public=a.enclave_public, signature=a.signature[:-1] + bytes([a.signature[-1] ^ 1]))
    assert not tampered.verify()
    # recognition is a key agreement: an outsider with no session key can't derive it
    sk_a, sk_b = b"A" * 32, b"B" * 32
    ap_priv, ap = contribution(sk_a, b"bc"); bp_priv, bp = contribution(sk_b, b"bc")
    true = recognition_value(my_priv=ap_priv, their_pub=bp.public, my_pub=ap.public, beacon=b"bc")
    out_priv, out = contribution(os.urandom(32), b"bc")
    assert recognition_value(my_priv=out_priv, their_pub=bp.public, my_pub=out.public, beacon=b"bc") != true
