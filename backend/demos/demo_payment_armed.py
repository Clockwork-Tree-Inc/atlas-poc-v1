"""Arm-per-use payment flow — PROTOCOL-LOGIC SIMULATION (Payment spec §4).

⚠️  THIS IS NOT AIR-GAPPED. The air-gap security property exists only with the
physical Card 2 over a real NFC/APDU session, gated by Step Zero on hardware
(Payment spec §1). This demo runs the protocol LOGIC in-process with a *modelled*
card so the binding / freshness / single-use behaviour is observable and the
adversarial cases are demonstrated. Do not present this as a working air gap.

Run:  python -m demos.demo_payment_armed     (from backend/)
"""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from atlas.liveness.attestation import AttestationSubsystem
from atlas.liveness.bayes import LivenessGate
from atlas.liveness.synthetic import live_stream
from atlas.payment import (
    ArmingRefused, CardRefused, DoubleSpend, EnclaveArmingAuthority,
    NullifierRegistry, PaymentCard, PaymentVerifier, SideButtonIntent, TransactionDescriptor,
)


def banner(t): print("\n" + "=" * 70 + f"\n{t}\n" + "=" * 70)


def live(att):
    g = LivenessGate()
    for _, (a, b) in live_stream(40):
        g.update(p_s_given_live=a, p_s_given_not_live=b)
    return att.attest(g.state(sensor_digest=b"s", drand_round=b"\x00" * 8))


def main() -> int:
    banner("ATLAS — arm-per-use payment (PROTOCOL-LOGIC SIM · NOT air-gapped)")
    print("Air gap requires the physical Card 2 + NFC Step Zero on hardware (spec §1).")

    enclave = EnclaveArmingAuthority()
    card = PaymentCard(enclave_arming_public=enclave.public_key)
    att = AttestationSubsystem()
    button = SideButtonIntent()
    verifier = PaymentVerifier(NullifierRegistry())

    d = TransactionDescriptor(amount=1299, recipient_id="merchant-42",
                              nonce=os.urandom(16).hex(), timestamp=int(time.time()), epoch=1)
    print(f"\nPayment: {d.amount} → {d.recipient_id}  nonce={d.nonce[:12]}…")

    banner("ARM-PER-USE ROUND TRIP")
    print("1. card tap → issue fresh card_nonce")
    card_id, card_nonce = card.issue_challenge()
    print(f"   card_id={card_id.hex()}  card_nonce={card_nonce.hex()[:12]}…")
    print("2. verified-human gate: liveness (ring+Enclave) + deliberate side-button press")
    arming = enclave.mint(descriptor=d, card_id=card_id, card_nonce=card_nonce,
                          liveness=live(att), intent=button.press())
    print("3. Enclave mints arming bound to THIS descriptor + THIS card")
    print("4. card verifies arming, signs exactly one transaction")
    payment_sig = card.sign(d, arming)
    print(f"   payment_sig={payment_sig.hex()[:24]}…")
    print("5. submit → verifier checks signature + nullifies nonce")
    assert verifier.verify_and_submit(d, payment_sig, card.public_key)
    print("   ACCEPTED ✓")

    banner("ADVERSARIAL — the two-factor air gap (logic)")
    # stolen card, no phone arming
    cid, cn = card.issue_challenge()
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from atlas.payment.enclave_arming import arming_message, Arming
    forged = Arming(signature=Ed25519PrivateKey.generate().sign(arming_message(d, cid, cn)),
                    descriptor_hash=b"", card_id=cid, card_nonce=cn)
    try:
        card.sign(d, forged); print("  !! stolen-card forged arming accepted — FAIL"); return 1
    except CardRefused:
        print("  stolen card + forged arming → card REFUSES ✓")
    # no side button
    cid, cn = card.issue_challenge()
    try:
        enclave.mint(descriptor=d, card_id=cid, card_nonce=cn, liveness=live(att), intent=None)
        print("  !! arming minted without intent — FAIL"); return 1
    except ArmingRefused:
        print("  no side-button press → Enclave mints NO arming ✓")
    # replay descriptor
    try:
        verifier.verify_and_submit(d, payment_sig, card.public_key)
        print("  !! descriptor re-submit accepted — FAIL"); return 1
    except DoubleSpend:
        print("  re-submit used descriptor → nullifier REJECTS ✓")

    banner("SIM PASS — protocol logic holds (review + Step Zero still required)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
