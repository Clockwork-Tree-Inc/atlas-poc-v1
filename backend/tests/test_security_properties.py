"""Adversarial security-property tests — XIV.5 §21, tier 1.

These are deliberately written as "an attacker tries X; assert X fails", not
"the function returns the expected value on normal input". Each test names the
property and the attacker capability it models. Read alongside SECURITY_TESTS.md,
which classifies the whole suite into security-property vs functional vs gaps.
"""

import os

import pytest

from atlas.beacon import ArrivalTiming, LocalBeacon, ServerQRNG
from atlas.crypto.primitives import aead_decrypt
from atlas.keys.derivation import derive_session_key_decoupled, ratchet
from atlas.keys.identity import build_identity_tree
from atlas.params import CONTEXT_TUNNEL
from atlas.session.device import Device, EpochInputs
from atlas.session.recognition import contribution, evolve_tunnel_key, recognition_value
from atlas.session.tunnel import SendMode, open_message, seal


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _pair(boot=None):
    seed = os.urandom(32)
    boot = boot or os.urandom(32)
    A = Device("A", build_identity_tree(seed), bootstrap_tunnel_key=boot)
    B = Device("B", build_identity_tree(seed), bootstrap_tunnel_key=boot)
    return A, B


def _epoch(A, B, *, lk, epoch_key, drand_round, beacon_label):
    from atlas.session import establish_hybrid_tunnel
    A.advance_epoch_present(lk=lk, epoch_key=epoch_key, drand_round=drand_round)
    B.advance_epoch_present(lk=lk, epoch_key=epoch_key, drand_round=drand_round)
    tA, tB = establish_hybrid_tunnel(A, B, beacon_label)
    assert tA == tB
    return tA


# ---------------------------------------------------------------------------
# Corrected §2.3 ONE-PRINCIPLE: value = clean QRNG; timing TIMES the firing and
# gates operations but NEVER enters a value. We hold the entropy core CONSTANT so
# timing is the only variable; the LK value must NOT change (timing not in value),
# while the firing SCHEDULE must (timing drives when it fires). Forward secrecy
# comes from the fresh QRNG core per firing plus the ratchet chain, not from
# mixing timing into the value.
# ---------------------------------------------------------------------------

def test_timing_times_the_firing_never_enters_the_lk_value():
    q = ServerQRNG()
    core = os.urandom(32)  # held constant across both fires
    epoch = b"\x00" * 8
    fast = ArrivalTiming(timestamps=[0.0, 0.10, 0.20])
    slow = ArrivalTiming(timestamps=[0.0, 0.50, 1.30])
    d_fast = q.fire(fast, epoch, entropy_core=core)
    d_slow = q.fire(slow, epoch, entropy_core=core)
    # Same core + same epoch, DIFFERENT timing -> SAME value (timing NOT in value).
    assert d_fast.randomness == d_slow.randomness, "timing leaked into the LK value"
    # The value is a clean function of the QRNG core: fresh core -> different value.
    assert q.fire(fast, epoch, entropy_core=os.urandom(32)).randomness != d_fast.randomness
    # Timing instead drives the firing SCHEDULE (deterministic in the arrival digest).
    assert d_fast.next_sampling_offset_s == q.base_period_s + (fast.digest()[0] / 255.0) * q.base_period_s
    assert d_slow.next_sampling_offset_s == q.base_period_s + (slow.digest()[0] / 255.0) * q.base_period_s
    # timing_commitment is retained for schedule/audit but is NOT part of the value.
    assert d_fast.timing_commitment == fast.digest()


# ---------------------------------------------------------------------------
# Forward secrecy: capture a LATER key, you cannot read an EARLIER epoch's
# ciphertext. Attacker capability: full compromise of epoch e+1 key material.
# ---------------------------------------------------------------------------

def test_forward_secrecy_later_key_cannot_read_earlier_epoch_ciphertext():
    A, B = _pair()
    beacon = LocalBeacon(period_s=3.0)
    # epoch e
    re = beacon.round_at(1.0)
    t_e = _epoch(A, B, lk=b"L1" * 16, epoch_key=re.randomness, drand_round=re.drand_round(),
                 beacon_label=b"comp|" + re.drand_round())
    msg_e = seal(b"epoch-e secret", mode=SendMode.NORMAL, key=t_e)
    # epoch e+1: beacon advances, tunnel re-keys
    re1 = beacon.round_at(5.0)
    t_e1 = _epoch(A, B, lk=b"L2" * 16, epoch_key=re1.randomness, drand_round=re1.drand_round(),
                  beacon_label=b"comp|" + re1.drand_round())
    assert t_e1 != t_e
    # Attacker who captured ONLY the later key t_e1 cannot read the earlier message.
    with pytest.raises(Exception):
        open_message(msg_e, key=t_e1)


# ---------------------------------------------------------------------------
# Replay / epoch-binding: a recognition/tunnel value captured in epoch e is
# inert once the beacon advances. Attacker capability: replay last epoch's
# tunnel key against this epoch's traffic.
# ---------------------------------------------------------------------------

def test_replayed_recognition_is_rejected_after_beacon_advance():
    A, B = _pair()
    beacon = LocalBeacon(period_s=3.0)
    re = beacon.round_at(1.0)
    captured = _epoch(A, B, lk=b"L1" * 16, epoch_key=re.randomness, drand_round=re.drand_round(),
                      beacon_label=b"comp|" + re.drand_round())
    # beacon advances; new epoch traffic is sealed under the new tunnel key
    re1 = beacon.round_at(5.0)
    fresh = _epoch(A, B, lk=b"L2" * 16, epoch_key=re1.randomness, drand_round=re1.drand_round(),
                   beacon_label=b"comp|" + re1.drand_round())
    current_msg = seal(b"this-epoch traffic", mode=SendMode.NORMAL, key=fresh)
    # Replaying the captured (stale) recognition tunnel key cannot read it.
    assert captured != fresh
    with pytest.raises(Exception):
        open_message(current_msg, key=captured)


def test_recognition_is_constant_within_epoch_but_changes_with_beacon():
    # The spec acknowledges recognition is replayable WITHIN an epoch (constant
    # until the beacon advances) and that a max epoch duration forces a re-key.
    # Assert exactly that boundary: same beacon -> same value; new beacon -> new.
    A, B = _pair(boot=b"\x07" * 32)
    inp = dict(lk=b"L" * 32, epoch_key=b"E" * 32, drand_round=b"\x00" * 8)
    A.advance_epoch_present(**inp); B.advance_epoch_present(**inp)
    ap, apub = contribution(A.session.key, b"beacon-r1")
    bp, bpub = contribution(B.session.key, b"beacon-r1")
    rec1 = recognition_value(my_priv=ap, their_pub=bpub.public, my_pub=apub.public, beacon=b"beacon-r1")
    rec1b = recognition_value(my_priv=ap, their_pub=bpub.public, my_pub=apub.public, beacon=b"beacon-r1")
    rec2 = recognition_value(my_priv=ap, their_pub=bpub.public, my_pub=apub.public, beacon=b"beacon-r2")
    assert rec1 == rec1b          # constant within an epoch (honest replay window)
    assert rec1 != rec2           # advances with the beacon


# ---------------------------------------------------------------------------
# Off-device rooting: device-local material alone cannot produce a valid session
# key / recognition without the beacon + LK. Attacker capability: full control of
# one device's local secrets, but not the live beacon/QRNG inputs.
# ---------------------------------------------------------------------------

def test_off_device_rooting_session_key_requires_beacon_and_lk():
    # Same device-local prev/local key, but a different beacon epoch_key or LK
    # yields a different session key -> local material alone is insufficient.
    common = dict(pole_value=b"Q" * 32, prev_key=b"\x00" * 32,
                  context_separator=CONTEXT_TUNNEL, drand_round=b"\x00" * 8)
    real = derive_session_key_decoupled(lk=b"L" * 32, epoch_key=b"E" * 32, **common)
    wrong_beacon = derive_session_key_decoupled(lk=b"L" * 32, epoch_key=b"X" * 32, **common)
    wrong_lk = derive_session_key_decoupled(lk=b"Z" * 32, epoch_key=b"E" * 32, **common)
    assert real.key != wrong_beacon.key
    assert real.key != wrong_lk.key


def test_off_device_rooting_tunnel_diverges_without_shared_beacon():
    # Two devices that do NOT share the same beacon label cannot agree a tunnel,
    # so an attacker who can't supply the live beacon can't reconstruct it.
    A, B = _pair()
    inp = dict(lk=b"L" * 32, epoch_key=b"E" * 32, drand_round=b"\x00" * 8)
    A.advance_epoch_present(**inp); B.advance_epoch_present(**inp)
    ap, apub = contribution(A.session.key, b"beacon-A")
    bp, bpub = contribution(B.session.key, b"beacon-B")  # different beacon
    ra = recognition_value(my_priv=ap, their_pub=bpub.public, my_pub=apub.public, beacon=b"beacon-A")
    rb = recognition_value(my_priv=bp, their_pub=apub.public, my_pub=bpub.public, beacon=b"beacon-B")
    assert ra != rb  # no shared beacon -> no shared recognition


# ---------------------------------------------------------------------------
# Recognition — the CLASSICAL X25519 component's threat boundary.
#
# These tests pin the bounds of the classical recognition_value primitive (the
# X25519 half of the tunnel):
#   * an OUTSIDER with NEITHER session key CANNOT compute it (DH security), and
#   * EITHER endpoint's session key + the public wire IS sufficient to recompute
#     the CLASSICAL recognition value — the normal 2-party-DH bound.
# NOTE: the actual core tunnel is now the HYBRID ML-KEM + X25519 handshake (see
# test_hybrid_tunnel_* below), which CLOSES the one-endpoint gap — the ephemeral
# ML-KEM secrets are not derived from the session key, so one session key + the
# wire no longer reconstructs the real tunnel.
# ---------------------------------------------------------------------------

def test_recognition_outsider_without_any_session_key_cannot_compute():
    A, B = _pair(boot=b"\x09" * 32)
    inp = dict(lk=b"L" * 32, epoch_key=b"E" * 32, drand_round=b"\x00" * 8)
    A.advance_epoch_present(**inp); B.advance_epoch_present(**inp)
    ap, apub = contribution(A.session.key, b"beacon-r1")
    bp, bpub = contribution(B.session.key, b"beacon-r1")
    true_rec = recognition_value(my_priv=ap, their_pub=bpub.public, my_pub=apub.public, beacon=b"beacon-r1")
    # Outsider sees apub/bpub but holds no session key -> no private contribution.
    out_priv, out_pub = contribution(os.urandom(32), b"beacon-r1")
    out_rec = recognition_value(my_priv=out_priv, their_pub=bpub.public, my_pub=out_pub.public, beacon=b"beacon-r1")
    assert out_rec != true_rec


def test_recognition_one_endpoint_key_plus_wire_reconstructs_CLASSICAL_component():
    # The CLASSICAL X25519 component alone: one endpoint's session key + the wire
    # recomputes the classical recognition value (normal 2-party-DH bound). The
    # hybrid tunnel below removes this as a tunnel-level weakness.
    A, B = _pair(boot=b"\x09" * 32)
    inp = dict(lk=b"L" * 32, epoch_key=b"E" * 32, drand_round=b"\x00" * 8)
    A.advance_epoch_present(**inp); B.advance_epoch_present(**inp)
    ap, apub = contribution(A.session.key, b"beacon-r1")
    bp, bpub = contribution(B.session.key, b"beacon-r1")
    true_rec = recognition_value(my_priv=ap, their_pub=bpub.public, my_pub=apub.public, beacon=b"beacon-r1")
    a_priv2, a_pub2 = contribution(A.session.key, b"beacon-r1")
    attacker_rec = recognition_value(my_priv=a_priv2, their_pub=bpub.public, my_pub=a_pub2.public, beacon=b"beacon-r1")
    assert attacker_rec == true_rec


# ---------------------------------------------------------------------------
# Hybrid PQ tunnel — the core tunnel is ML-KEM-768 + X25519 (post-quantum).
# ---------------------------------------------------------------------------

def test_hybrid_tunnel_is_post_quantum_and_mlkem_is_load_bearing():
    from atlas.session import establish_hybrid_tunnel
    from atlas.session.recognition import (
        hybrid_contribution, hybrid_encapsulate, hybrid_recognition_value,
    )
    A, B = _pair()
    inp = dict(lk=b"L" * 32, epoch_key=b"E" * 32, drand_round=b"\x00" * 8)
    A.advance_epoch_present(**inp); B.advance_epoch_present(**inp)

    # the on-wire contribution carries a real ML-KEM-768 encapsulation key
    a_x, a_dk, a_pub = hybrid_contribution(A.session.key, b"bcn")
    assert len(a_pub.mlkem_ek) == 1184
    ct, ss = hybrid_encapsulate(a_pub)
    assert len(ct) == 1088 and len(ss) == 32

    # two devices agree on the same hybrid tunnel
    tA, tB = establish_hybrid_tunnel(A, B, b"bcn")
    assert tA == tB

    # ML-KEM is LOAD-BEARING: recomputing recognition with a WRONG ML-KEM secret
    # (i.e. classical material only) yields a different value -> a quantum
    # attacker who breaks only X25519 cannot reach the tunnel.
    b_x, b_dk, b_pub = hybrid_contribution(B.session.key, b"bcn")
    ct_ab, ss_ab = hybrid_encapsulate(b_pub)   # A->B
    ct_ba, ss_ba = hybrid_encapsulate(a_pub)   # B->A
    real = hybrid_recognition_value(my_x_priv=a_x, my_mlkem_dk=a_dk, my_pub=a_pub,
                                    their_pub=b_pub, their_ct=ct_ba, my_ss_self=ss_ab, beacon=b"bcn")
    # same X25519 transcript but a zeroed ML-KEM secret -> different recognition
    forged = hybrid_recognition_value(my_x_priv=a_x, my_mlkem_dk=a_dk, my_pub=a_pub,
                                      their_pub=b_pub, their_ct=ct_ba, my_ss_self=b"\x00" * 32, beacon=b"bcn")
    assert real != forged


# ---------------------------------------------------------------------------
# Containment: a liveness break wipes the live session key AND any key derived
# after the wipe is impossible; prior in-RAM keys are dead. Attacker capability:
# seize the device immediately after a liveness break.
# ---------------------------------------------------------------------------

def test_containment_session_inert_after_liveness_break():
    from atlas.liveness.bayes import LivenessGate
    from atlas.liveness.synthetic import spoof_stream

    A, _ = _pair()
    A.advance_epoch_present(lk=b"L" * 32, epoch_key=b"E" * 32, drand_round=b"\x00" * 8)
    _ = A.session.key  # alive now
    # liveness breaks -> attestation marks suspicious -> wipe callback fires
    g = LivenessGate()
    for _, (psl, psnl) in spoof_stream(40):
        g.update(p_s_given_live=psl, p_s_given_not_live=psnl)
    pole = g.state(sensor_digest=b"d", drand_round=b"\x00" * 8)
    assert A.attestation.attest(pole) is None  # break detected
    # the live session key is now inert
    with pytest.raises(Exception):
        _ = A.session.key
    # and no session-derived copy survives in RAM (ratchet prev-key wiped too)
    assert A._prev_session_bytes == b"\x00" * 32
