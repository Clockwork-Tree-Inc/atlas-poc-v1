"""Session layer: recognition/tunnel, vault, two send modes, containment (§4, §9)."""

import os

import pytest

from atlas.beacon import LocalBeacon
from atlas.crypto import kem
from atlas.keys.derivation import ratchet
from atlas.keys.identity import build_identity_tree
from atlas.liveness.attestation import AttestationSubsystem
from atlas.liveness.bayes import LivenessGate
from atlas.liveness.synthetic import live_stream
from atlas.session.device import Device, EpochInputs
from atlas.session.tunnel import AccessDenied, SendMode, open_message, seal
from atlas.session.vault import Vault


def _pair():
    seed = os.urandom(32)
    boot = os.urandom(32)
    A = Device("A", build_identity_tree(seed), bootstrap_tunnel_key=boot)
    B = Device("B", build_identity_tree(seed), bootstrap_tunnel_key=boot)
    return A, B


def test_no_continuity_no_epoch_key_no_lk_no_ratchet():
    """FIX #7 + #15 (structural chain, §2.3): continuity=yes -> unwrap epoch key
    -> unlock LK -> session key. No continuity -> no unwrap -> no LK -> no ratchet,
    by construction. The epoch key is public but useless without the (continuity-
    gated) presence unwrap. There is no advance_epoch path that skips the chain."""
    from atlas.session.device import PresenceRequired
    from atlas.session.presence import wrap_lk
    from atlas.liveness.bayes import PoLEState
    A = Device("A", build_identity_tree(os.urandom(32)), bootstrap_tunnel_key=os.urandom(32))
    lk, ek, eid = b"L" * 32, b"E" * 32, b"\x00" * 8
    # server side: epoch key WRAPS the LK; presence WRAPS the epoch key
    w_lk = wrap_lk(lk, epoch_key=ek, drand_round=eid)
    w_ek = A.wrap_epoch_key(ek, eid)
    live = PoLEState(p_live=1.0, state_digest=b"d", drand_round=eid, operate=True)
    dead = PoLEState(p_live=0.0, state_digest=b"d", drand_round=eid, operate=False)

    def go(dev, *, wep=w_ek, wlk=w_lk, bio=None, pole=live):
        return dev.advance_epoch(wrapped_epoch_key=wep, wrapped_lk=wlk, drand_round=eid,
                                 live_biometric=bio if bio is not None else dev._enrolled_biometric,
                                 pole=pole)

    # present -> full chain succeeds
    sk = go(A)
    assert sk.key and A.session.key == sk.key
    # continuity broken (pole not operating) -> no release -> no epoch-key -> no LK
    with pytest.raises(PresenceRequired):
        go(A, pole=dead)
    # not the enrolled live user (impostor biometric) -> enclave won't release
    with pytest.raises(PresenceRequired):
        go(A, bio=os.urandom(256))
    # a different device cannot unwrap the epoch key (enrollment secret differs)
    B = Device("B", build_identity_tree(os.urandom(32)), bootstrap_tunnel_key=os.urandom(32))
    with pytest.raises(PresenceRequired):
        go(B)
    # tampered wrapped epoch key -> unwrap fails closed
    with pytest.raises(PresenceRequired):
        go(A, wep=w_ek[:-1] + bytes([w_ek[-1] ^ 1]))
    # LK wrapped under a DIFFERENT epoch key -> the unwrapped epoch key can't unlock it
    with pytest.raises(PresenceRequired):
        go(A, wlk=wrap_lk(lk, epoch_key=b"Z" * 32, drand_round=eid))


def _recognise(A, B, beacon):
    # Core tunnel is the hybrid ML-KEM + X25519 handshake.
    from atlas.session import establish_hybrid_tunnel
    return establish_hybrid_tunnel(A, B, beacon)


def test_recognition_yields_shared_tunnel_key_without_sending_session_keys():
    A, B = _pair()
    inp = EpochInputs(lk=b"L" * 32, epoch_key=b"E" * 32, drand_round=b"\x00" * 8)
    A.advance_epoch_present(lk=inp.lk, epoch_key=inp.epoch_key, drand_round=inp.drand_round)
    B.advance_epoch_present(lk=inp.lk, epoch_key=inp.epoch_key, drand_round=inp.drand_round)
    # A and B have DIFFERENT session keys (each composed locally)...
    assert A.session.key != B.session.key
    # ...yet recognition produces an identical tunnel key.
    tA, tB = _recognise(A, B, b"beacon-r1")
    assert tA == tB


def test_recognition_rekeys_when_beacon_advances():
    A, B = _pair()
    inp = EpochInputs(lk=b"L" * 32, epoch_key=b"E" * 32, drand_round=b"\x00" * 8)
    A.advance_epoch_present(lk=inp.lk, epoch_key=inp.epoch_key, drand_round=inp.drand_round); B.advance_epoch_present(lk=inp.lk, epoch_key=inp.epoch_key, drand_round=inp.drand_round)
    t1a, t1b = _recognise(A, B, b"beacon-r1")
    t2a, t2b = _recognise(A, B, b"beacon-r2")
    assert t1a == t1b and t2a == t2b and t1a != t2a  # every re-recognition is a re-key


def test_outsider_cannot_compute_recognition():
    A, B = _pair()
    inp = EpochInputs(lk=b"L" * 32, epoch_key=b"E" * 32, drand_round=b"\x00" * 8)
    A.advance_epoch_present(lk=inp.lk, epoch_key=inp.epoch_key, drand_round=inp.drand_round); B.advance_epoch_present(lk=inp.lk, epoch_key=inp.epoch_key, drand_round=inp.drand_round)
    tA, tB = _recognise(A, B, b"beacon-r1")
    # An eavesdropper, C, sees only the public contributions but holds neither
    # live session key; pairing two fresh devices gives a different tunnel key.
    C, D = _pair()
    C.advance_epoch_present(lk=inp.lk, epoch_key=inp.epoch_key, drand_round=inp.drand_round); D.advance_epoch_present(lk=inp.lk, epoch_key=inp.epoch_key, drand_round=inp.drand_round)
    tC, _ = _recognise(C, D, b"beacon-r1")
    assert tC != tA


def test_vault_encrypted_at_rest_and_pqc_wrap():
    v = Vault(os.urandom(32))
    v.put("doc", b"top secret bytes")
    assert v.get("doc") == b"top secret bytes"
    assert b"top secret bytes" not in v.raw_at_rest("doc")
    kp = kem.generate_keypair()
    bundle = Vault.wrap_key_for_recipient(kp.public, b"K" * 32)
    assert Vault.unwrap_key(kp, bundle) == b"K" * 32


def test_mode1_normal_encrypted_text():
    A, B = _pair()
    inp = EpochInputs(lk=b"L" * 32, epoch_key=b"E" * 32, drand_round=b"\x00" * 8)
    A.advance_epoch_present(lk=inp.lk, epoch_key=inp.epoch_key, drand_round=inp.drand_round); B.advance_epoch_present(lk=inp.lk, epoch_key=inp.epoch_key, drand_round=inp.drand_round)
    tA, tB = _recognise(A, B, b"beacon-r1")
    m = seal(b"hello B", mode=SendMode.NORMAL, key=tA)
    assert open_message(m, key=tB) == b"hello B"


def test_mode2_verified_human_only_gate():
    A, B = _pair()
    inp = EpochInputs(lk=b"L" * 32, epoch_key=b"E" * 32, drand_round=b"\x00" * 8)
    A.advance_epoch_present(lk=inp.lk, epoch_key=inp.epoch_key, drand_round=inp.drand_round); B.advance_epoch_present(lk=inp.lk, epoch_key=inp.epoch_key, drand_round=inp.drand_round)
    tA, tB = _recognise(A, B, b"beacon-r1")
    comp = b"epoch-component-r1"

    # B is a live human on-network
    gate = LivenessGate()
    for _, (psl, psnl) in live_stream(40):
        gate.update(p_s_given_live=psl, p_s_given_not_live=psnl)
    pole = gate.state(sensor_digest=b"d", drand_round=inp.drand_round)
    provider = lambda ch: B.attestation.attest(pole, challenge=ch)

    m = seal(b"eyes only", mode=SendMode.VERIFIED_HUMAN, key=tA,
             beacon_component=comp, recipient_enclave_public=B.attestation.enclave_key.public)

    # verified-live, on-network -> opens
    assert open_message(m, key=tB, current_beacon_component=comp,
                        attestation_provider=provider) == b"eyes only"
    assert any("granted" in e for e in m.access_log)

    # offline -> denied
    with pytest.raises(AccessDenied):
        open_message(m, key=tB, current_beacon_component=None, attestation_provider=provider)
    # not-live (no attestation) -> denied
    with pytest.raises(AccessDenied):
        open_message(m, key=tB, current_beacon_component=comp, attestation_provider=lambda: None)
    # epoch expiry / revocation -> denied
    with pytest.raises(AccessDenied):
        open_message(m, key=tB, current_beacon_component=b"stale", attestation_provider=provider)


def test_mode2_rejects_replayed_stale_attestation():
    """Freshness nonce (§9.2 anti-replay): a captured operate=True attestation —
    even one valid for THIS epoch and enclave — cannot be replayed at a later
    view. open_message picks a fresh challenge each time; a static attestation
    answers the wrong (old) challenge and is denied. A genuinely live provider
    (re-signs the fresh challenge) still opens it."""
    A, B = _pair()
    inp = EpochInputs(lk=b"L" * 32, epoch_key=b"E" * 32, drand_round=b"\x00" * 8)
    A.advance_epoch_present(lk=inp.lk, epoch_key=inp.epoch_key, drand_round=inp.drand_round); B.advance_epoch_present(lk=inp.lk, epoch_key=inp.epoch_key, drand_round=inp.drand_round)
    tA, tB = _recognise(A, B, b"beacon-r1")
    comp = b"epoch-component-r1"
    gate = LivenessGate()
    for _, (psl, psnl) in live_stream(40):
        gate.update(p_s_given_live=psl, p_s_given_not_live=psnl)
    pole = gate.state(sensor_digest=b"d", drand_round=inp.drand_round)
    m = seal(b"eyes only", mode=SendMode.VERIFIED_HUMAN, key=tA,
             beacon_component=comp, recipient_enclave_public=B.attestation.enclave_key.public)

    # An attacker captures one valid attestation and replays the same object.
    captured = B.attestation.attest(pole, challenge=b"old-challenge")
    assert captured.verify() and captured.operate            # it IS a valid attestation
    with pytest.raises(AccessDenied):
        open_message(m, key=tB, current_beacon_component=comp,
                     attestation_provider=lambda ch: captured)

    # The live recipient, who can re-sign whatever challenge is asked, opens it.
    live = lambda ch: B.attestation.attest(pole, challenge=ch)
    assert open_message(m, key=tB, current_beacon_component=comp,
                        attestation_provider=live) == b"eyes only"


def test_unbootstrapped_devices_fail_closed():
    """Omitting the in-person bootstrap PSK must FAIL CLOSED: each device gets a
    fresh random root (not a public all-zero constant), so two un-bootstrapped
    devices do NOT silently converge on a shared tunnel — the in-person binding
    that makes recognition MITM-resistant can't be voided by forgetting the PSK."""
    from atlas.session import establish_hybrid_tunnel
    A = Device("A", build_identity_tree(os.urandom(32)))   # no bootstrap_tunnel_key
    B = Device("B", build_identity_tree(os.urandom(32)))
    assert not A.bootstrapped and not B.bootstrapped
    assert A.tunnel_key != b"\x00" * 32 and A.tunnel_key != B.tunnel_key
    inp = EpochInputs(lk=b"L" * 32, epoch_key=b"E" * 32, drand_round=b"\x00" * 8)
    A.advance_epoch_present(lk=inp.lk, epoch_key=inp.epoch_key, drand_round=inp.drand_round); B.advance_epoch_present(lk=inp.lk, epoch_key=inp.epoch_key, drand_round=inp.drand_round)
    tA, tB = establish_hybrid_tunnel(A, B, b"beacon")
    assert tA != tB                                   # no shared tunnel without the PSK


def test_stolen_device_cannot_open_mode2_after_wipe():
    """A stolen device: liveness breaks -> RAM wipe of the tunnel key + no live
    attestation. It genuinely cannot open Mode-2 content (§9.2)."""
    A, B = _pair()
    inp = EpochInputs(lk=b"L" * 32, epoch_key=b"E" * 32, drand_round=b"\x00" * 8)
    A.advance_epoch_present(lk=inp.lk, epoch_key=inp.epoch_key, drand_round=inp.drand_round); B.advance_epoch_present(lk=inp.lk, epoch_key=inp.epoch_key, drand_round=inp.drand_round)
    tA, tB = _recognise(A, B, b"beacon-r1")
    comp = b"epoch-component-r1"
    m = seal(b"eyes only", mode=SendMode.VERIFIED_HUMAN, key=tA,
             beacon_component=comp, recipient_enclave_public=B.attestation.enclave_key.public)
    # Thief holds the device but is not the live human: the enclave refuses to
    # produce an operating attestation.
    from atlas.liveness.bayes import LivenessGate
    from atlas.liveness.synthetic import spoof_stream
    g = LivenessGate()
    for _, (psl, psnl) in spoof_stream(40):
        g.update(p_s_given_live=psl, p_s_given_not_live=psnl)
    spoof_pole = g.state(sensor_digest=b"d", drand_round=inp.drand_round)
    provider = lambda: B.attestation.attest(spoof_pole)  # returns None + wipes
    with pytest.raises(AccessDenied):
        open_message(m, key=tB, current_beacon_component=comp, attestation_provider=provider)


def test_message_ratchet_forward_secrecy_and_break_in_recovery():
    """§10.1: a captured earlier key cannot read the later message.

    The ratchet mixes FRESH SECRET entropy each step, so knowing K[t] (earlier)
    is insufficient to derive K[t+1] without entropy_t; and the one-way hash
    means K[t+1] (later) cannot reveal K[t]."""
    A, _ = _pair()
    k0 = os.urandom(32)
    k1, entropy1 = A.message_ratchet_step(k0, beacon_t=b"b1", drand_round=b"\x00" * 8)
    # Attacker captured k0 but NOT the secret entropy1: cannot reach k1.
    guess = ratchet(k0, entropy_t=b"\x00" * 32, beacon_t=b"b1", drand_round=b"\x00" * 8)
    assert guess != k1
    # With the real (secret) entropy, the ratchet is reproducible.
    assert ratchet(k0, entropy_t=entropy1, beacon_t=b"b1", drand_round=b"\x00" * 8) == k1
