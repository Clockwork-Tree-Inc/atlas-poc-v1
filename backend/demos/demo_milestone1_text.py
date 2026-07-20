"""Milestone 1 exit test (§13, §10.1) — runnable end to end on the Mac/CI.

  "Encrypted text message A->B over the recognition-seeded tunnel; 2nd message
   proves forward secrecy. Sent in Mode 1 and again in Mode 2 to show the gate."

This is the backend-to-backend demonstration of Milestone 1. On real hardware
the same protocol core drives two iPhone wallets; here both wallets run in one
process so the whole loop is observable.

Run:  python -m demos.demo_milestone1_text       (from backend/)
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from atlas.beacon import ArrivalTiming, LocalBeacon, ServerQRNG
from atlas.keys.derivation import ratchet
from atlas.keys.identity import build_identity_tree
from atlas.liveness.bayes import LivenessGate
from atlas.liveness.synthetic import live_stream, spoof_stream
from atlas.session.device import Device, EpochInputs, establish_hybrid_tunnel
from atlas.session.tunnel import AccessDenied, SendMode, open_message, seal


def banner(t: str) -> None:
    print("\n" + "=" * 70 + f"\n{t}\n" + "=" * 70)


def pole_for(stream_fn, drand_round: bytes):
    g = LivenessGate()
    for _, (psl, psnl) in stream_fn(40):
        g.update(p_s_given_live=psl, p_s_given_not_live=psnl)
    return g.state(sensor_digest=b"sensor", drand_round=drand_round)


def main() -> int:
    banner("ATLAS PoC — Milestone 1: encrypted text A->B (recognition-seeded tunnel)")

    # --- Shared in-person enrolment root (§6): the pair leaves the ritual with
    #     a common identity seed + bootstrap tunnel key. ---
    enrol_seed = os.urandom(32)
    bootstrap = os.urandom(32)
    A = Device("Wallet-A", build_identity_tree(enrol_seed), bootstrap_tunnel_key=bootstrap)
    B = Device("Wallet-B", build_identity_tree(enrol_seed), bootstrap_tunnel_key=bootstrap)
    print(f"Enrolled pair. Root handle: {A.identity.root_handle.hex()[:16]}…")

    # --- Beacons (§3): public drand stand-in + presence-fired server QRNG. ---
    beacon = LocalBeacon(genesis_time=0.0, period_s=3.0)
    qrng = ServerQRNG(base_period_s=3.0)

    def run_epoch(now: float, label: str):
        rnd = beacon.round_at(now)
        # Server QRNG fires from aggregate device arrival timing (§3.1), returns
        # ONLY timed randomness (the LK); each device composes its key locally.
        arrivals = ArrivalTiming(timestamps=[now, now + 0.18, now + 0.41])
        draw = qrng.fire(arrivals, rnd.drand_round())                       # LK (private QRNG)
        # Epoch key = network-public QRNG timed by the aggregate LK cadence — a
        # clean QRNG value, NOT drand (drand stays only as the timestamp witness
        # in `beacon_label` below).
        epoch_draw = qrng.fire(ArrivalTiming([now, now + 0.3, now + 0.7]), rnd.drand_round())
        inp = EpochInputs(lk=draw.randomness, epoch_key=epoch_draw.randomness, drand_round=rnd.drand_round())
        A.advance_epoch_present(lk=inp.lk, epoch_key=inp.epoch_key, drand_round=inp.drand_round)
        B.advance_epoch_present(lk=inp.lk, epoch_key=inp.epoch_key, drand_round=inp.drand_round)
        beacon_label = b"component|" + rnd.drand_round()
        # Core tunnel: hybrid ML-KEM-768 + X25519 recognition handshake (PQ).
        tA, tB = establish_hybrid_tunnel(A, B, beacon_label)
        print(f"\n[{label}] round={rnd.round}  A.session != B.session: "
              f"{A.session.key != B.session.key}  recognition tunnel match: {tA == tB}")
        assert tA == tB
        return tA, tB, rnd, beacon_label

    # --- Mode 1: normal encrypted text (§9.1) ---
    banner("MODE 1 — normal encrypted text")
    tA, tB, rnd, beacon_label = run_epoch(1.0, "epoch-1")
    m1 = seal(b"Message #1: hello from A", mode=SendMode.NORMAL, key=tA)
    print("A -> B ciphertext:", m1.ciphertext[:24].hex(), "…")
    print("B decrypts:        ", open_message(m1, key=tB).decode())

    # --- Forward secrecy: 2nd message over a ratcheted key (§10.1) ---
    banner("FORWARD SECRECY — 2nd message; a captured earlier key cannot read it")
    msg_key_1 = tA
    msg_key_2, secret_entropy = A.message_ratchet_step(msg_key_1, beacon_t=rnd.randomness, drand_round=rnd.drand_round())
    m2 = seal(b"Message #2: ratcheted", mode=SendMode.NORMAL, key=msg_key_2)
    # B ratchets with the same (transmitted-out-of-band-secret) entropy.
    b_key_2 = ratchet(msg_key_1, entropy_t=secret_entropy, beacon_t=rnd.randomness, drand_round=rnd.drand_round())
    print("B decrypts #2:     ", open_message(m2, key=b_key_2).decode())
    # Attacker holding ONLY the earlier key (msg_key_1) and the public beacon,
    # but not the secret ratchet entropy, cannot derive msg_key_2:
    attacker_guess = ratchet(msg_key_1, entropy_t=b"\x00" * 32, beacon_t=rnd.randomness, drand_round=rnd.drand_round())
    try:
        open_message(m2, key=attacker_guess)
        print("!! FORWARD SECRECY FAILED")
        return 1
    except Exception:
        print("Captured earlier key CANNOT read message #2  ✓ (forward secrecy holds)")

    # --- Mode 2: verified-human-only (§9.2) ---
    banner("MODE 2 — verified-human-only viewing")
    tA, tB, rnd, beacon_label = run_epoch(4.0, "epoch-2")
    epoch_component = b"component|" + rnd.drand_round()
    m3 = seal(b"Message #3: for verified human eyes only", mode=SendMode.VERIFIED_HUMAN,
              key=tA, beacon_component=epoch_component,
              recipient_enclave_public=B.attestation.enclave_key.public)

    live_pole = pole_for(live_stream, rnd.drand_round())
    live_provider = lambda ch: B.attestation.attest(live_pole, challenge=ch)
    out = open_message(m3, key=tB, current_beacon_component=epoch_component,
                       attestation_provider=live_provider, expected_drand_round=rnd.drand_round())
    print("Verified-live recipient on-network opens:", out.decode())

    print("\n-- adversaries cannot open the SAME message --")
    for label, kwargs in [
        ("offline holder", dict(current_beacon_component=None, attestation_provider=live_provider)),
        ("bot / script (not live)", dict(current_beacon_component=epoch_component, attestation_provider=lambda: None)),
        ("expired epoch / revoked", dict(current_beacon_component=b"stale", attestation_provider=live_provider)),
    ]:
        try:
            open_message(m3, key=tB, **kwargs)
            print(f"  !! {label} OPENED IT — FAIL"); return 1
        except AccessDenied as e:
            print(f"  {label:28s} -> DENIED ({e})")

    # stolen device: the live human is absent; PoLE breaks -> wipe + no attestation
    fresh_B_enclave = B.attestation  # the thief holds B's device
    spoof_pole = pole_for(spoof_stream, rnd.drand_round())
    thief_provider = lambda: fresh_B_enclave.attest(spoof_pole)
    try:
        open_message(m3, key=tB, current_beacon_component=epoch_component, attestation_provider=thief_provider)
        print("  !! stolen device OPENED IT — FAIL"); return 1
    except AccessDenied as e:
        print(f"  {'stolen device (no live human)':28s} -> DENIED ({e})")

    banner("MILESTONE 1 EXIT TEST: PASS")
    print("Mode 1 text A->B ✓   forward secrecy ✓   Mode 2 gate ✓")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
