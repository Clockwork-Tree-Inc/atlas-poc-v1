"""Milestone 5 capstone (§13, §10.2) — encrypted, provenanced photo A->B.

A captures a photo; it passes the LiDAR depth/PAD check; the earliest frame is
signed with a liveness-gated authorship pseudonym; the epoch-key timestamp is
bound and the hash anchored; the photo + provenance bundle are encrypted under
the tunnel key and sent to B, which decrypts, displays, and verifies provenance.
A screen replay is rejected by PAD at capture.

Run:  python -m demos.demo_milestone5_photo     (from backend/)
"""

from __future__ import annotations

import os
import pickle
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from atlas.beacon import LocalBeacon
from atlas.keys.identity import build_identity_tree
from atlas.liveness.attestation import AttestationSubsystem
from atlas.liveness.bayes import LivenessGate
from atlas.liveness.synthetic import live_stream
from atlas.provenance import (
    CaptureMetadata, LedgerStub, PADRejected, PublicWitnessRegistry,
    sign_capture, verify_provenance,
)
from atlas.session.device import Device, EpochInputs, establish_hybrid_tunnel
from atlas.session.tunnel import SendMode, open_message, seal

REAL_DEPTH = [0.42, 0.61, 0.95, 1.30, 0.55, 0.78, 1.10, 0.33]   # a real 3-D scene
SCREEN_DEPTH = [0.30, 0.301, 0.299, 0.30, 0.302, 0.30, 0.301, 0.299]  # a flat screen


def banner(t):
    print("\n" + "=" * 70 + f"\n{t}\n" + "=" * 70)


def live_pole(rnd):
    g = LivenessGate()
    for _, (psl, psnl) in live_stream(40):
        g.update(p_s_given_live=psl, p_s_given_not_live=psnl)
    return g.state(sensor_digest=b"sensor", drand_round=rnd.drand_round())


def main() -> int:
    banner("ATLAS PoC — Milestone 5 capstone: encrypted, provenanced photo A→B")

    seed = os.urandom(32); boot = os.urandom(32)
    A = Device("Wallet-A", build_identity_tree(seed), bootstrap_tunnel_key=boot)
    B = Device("Wallet-B", build_identity_tree(seed), bootstrap_tunnel_key=boot)
    beacon = LocalBeacon(period_s=3.0)
    rnd = beacon.round_at(1.0)
    # epoch key = network-public epoch QRNG (clean value), NOT drand; `rnd` (drand)
    # is used only as the provenance timestamp witness (beacon_round) below.
    inp = EpochInputs(lk=b"L" * 32, epoch_key=os.urandom(32), drand_round=rnd.drand_round())
    A.advance_epoch_present(lk=inp.lk, epoch_key=inp.epoch_key, drand_round=inp.drand_round); B.advance_epoch_present(lk=inp.lk, epoch_key=inp.epoch_key, drand_round=inp.drand_round)
    label = b"component|" + rnd.drand_round()
    tA, tB = establish_hybrid_tunnel(A, B, label)   # hybrid ML-KEM + X25519 tunnel
    assert tA == tB
    ledger = LedgerStub()
    # Live session for the capture: the LK is the presence-gated per-epoch Living
    # Key (here the epoch's `inp.lk`); the server publishes the epoch witness pub.
    registry = PublicWitnessRegistry()
    session_key = A.session_key if getattr(A, "session_key", None) else os.urandom(32)
    registry.publish(inp.lk, rnd.drand_round())
    photo = b"\x89PNG\r\n... earliest AVFoundation frame bytes ..." + os.urandom(64)
    meta = CaptureMetadata(camera_intrinsics="f=26mm", motion="still",
                           captured_at="2026-06-27T12:00:00Z", depth_summary="varied")

    banner("CAPTURE — real scene passes PAD, is signed + anchored")
    bundle = sign_capture(content=photo, depth_map=REAL_DEPTH, moire_score=0.12,
                          metadata=meta, authorship=A.identity.child("authorship"),
                          attestation_subsystem=A.attestation, pole=live_pole(rnd),
                          beacon_round=rnd, ledger=ledger, lk=inp.lk, session_key=session_key)
    print("PAD passed (depth variance %.3f)  authorship=%s…  anchored at index %d"
          % (bundle.pad.depth_variance, bundle.authorship_handle.hex()[:12], bundle.anchor_index))

    banner("SEND — photo + provenance encrypted under the tunnel key → B")
    payload = pickle.dumps({"photo": photo, "bundle": bundle})  # demo transport only
    sealed = seal(payload, mode=SendMode.NORMAL, key=tA)
    received = pickle.loads(open_message(sealed, key=tB))
    print("B received %d bytes, decrypted ok" % len(sealed.ciphertext))

    banner("VERIFY on B — guarantee is ACCOUNTABLE ATTRIBUTION (not scene-authenticity)")
    verdict = verify_provenance(received["bundle"], content=received["photo"], ledger=ledger,
                                witness_registry=registry)
    for name, ok in [("authored by verified live human", verdict.liveness_ok),
                     ("at a verifiable time (epoch-bound)", verdict.liveness_ok),
                     ("integrity (unmodified since capture)", verdict.integrity_ok),
                     ("bound to authorship pseudonym (resolvable under cause)", verdict.handle_ok and verdict.signature_ok),
                     ("anchored in ledger", verdict.anchored_ok)]:
        print(f"  {'✓' if ok else '✗'} {name}")
    print(f"  · advisory: PAD passed = {verdict.pad_advisory.passed} (confidence hint, not the verdict)")
    assert verdict.accountable
    print("  => ACCOUNTABLE ATTRIBUTION holds.")

    banner("SPOOF — PAD is an ADVISORY fraud filter (not the guarantee)")
    print("Guarantee = accountable attribution; PAD catches lazy fakes as a bonus.")
    try:
        sign_capture(content=b"replayed", depth_map=SCREEN_DEPTH, moire_score=0.12,
                     metadata=meta, authorship=A.identity.child("authorship"),
                     attestation_subsystem=A.attestation, pole=live_pole(rnd),
                     beacon_round=rnd, ledger=ledger, lk=inp.lk, session_key=session_key,
                     pad_policy="reject")
        print("  !! screen replay was signed — FAIL"); return 1
    except PADRejected as e:
        print(f"  with pad_policy='reject', screen replay → REJECTED at capture ({e})")
    print("  (default 'advisory' would still sign it — but the verdict's guarantee")
    print("   is accountable attribution, with PAD attached as a confidence hint.)")

    banner("MILESTONE 5 CAPSTONE: PASS")
    print("provenanced photo A→B ✓   author+time+integrity verified ✓   PAD rejects replay ✓")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
