# Atlas Payment Module — Assessment Package (Payment spec §8)

**Status: PROTOCOL-LOGIC PROTOTYPE · NOT FOR VALUE-BEARING USE.** This is the
artifact handed to the cryptographer / security reviewer and the §11 external
audit. It states the trust model, the MUSTs and whether each is tested or
assumed, the Step-Zero open questions, and the review gate. Per the spec, every
"MUST" is a review checkpoint, not a finished guarantee.

> Honesty line, stated plainly: **the air gap is NOT proven here.** The air-gap
> property exists only with the physical Card 2 over a real NFC/APDU session,
> which is gated by Step Zero on hardware (§1) — something this prototype cannot
> execute. What is built and tested is the *protocol logic* of the arm-per-use
> flow. A software card was deliberately **not** wired into the live demo as
> "air-gapped," because the spec forbids exactly that (§1).

## 1. What was built (and where)

| Piece | Location | Status |
|-------|----------|--------|
| Transaction descriptor + canonical bytes | `backend/atlas/payment/descriptor.py` | built + tested |
| Side-button intent gate (+ optional co-motion) | `backend/atlas/payment/intent.py` | built + tested |
| Enclave arming authority (gated on liveness + intent) | `backend/atlas/payment/enclave_arming.py` | built + tested |
| Card 2 model (on-card keygen, nonce, verify, single-sig) | `backend/atlas/payment/card.py` | built + tested |
| Nullifier + submit verifier | `backend/atlas/payment/nullifier.py` | built + tested |
| Adversarial test battery (§7.2) | `backend/tests/test_payment.py` (12 tests) | passing |
| Labeled sim demo | `backend/demos/demo_payment_armed.py` | runs |
| Swift logic mirror | `ios/AtlasCore/Sources/AtlasCore/Payment/Payment.swift` | source (uncompiled) |
| **Step Zero NFC probe** | `ios/AtlasApp/Payment/StepZeroNFCProbe.swift` | source — **must run on device first** |
| Card 2 NFC session | `ios/AtlasApp/Payment/Card2NFCSession.swift` | source (scaffold) |
| Enclave arming minter (LAContext side button) | `ios/AtlasApp/Payment/ArmingMinter.swift` | source |
| Card 2 JavaCard applet | `javacard/Card2Applet.java` | source (applet skeleton) |

## 2. Trust model (§3)

| Element | Holds | Proves | Never holds |
|---------|-------|--------|-------------|
| Card 2 (payment card) | payment private key (on-card, non-extractable) | possession of the air-gapped signer | the Enclave key |
| iPhone Secure Enclave + Atlas liveness/identity | the arming authority key | a verified live human deliberately authorizing THIS transaction | the card key |
| Side button | nothing (it's a gate) | deliberate in-the-moment human intent | any key |

**The two-factor air gap:** a payment needs BOTH the physical card (signer) AND
the phone's arming (verified-human authorization). Stolen card alone → no arming
→ no usable signature. Compromised phone alone → no card key → no payment
signature. Neither element holds the other's secret.

## 3. The MUSTs (§4/§7) — tested vs assumed

| MUST | Status in this prototype |
|------|--------------------------|
| Card key on-card generated, non-extractable | **Modeled + asserted** (`test_card_private_key_has_no_export_path`). On hardware: enforced by the secure element / `Card2Applet.genKeyPair`. **Assumed until the JavaCard build.** |
| Arming bound to the exact descriptor AND the card (card_nonce/card_id) | **Tested** (`test_arming_for_A_cannot_authorize_B`, `..._card_X_cannot_be_used_on_card_Y`). |
| Card refuses to sign without a valid, fresh, matching arming | **Tested** (`test_stolen_card_alone_cannot_sign`, `..._used_arming_cannot_be_re_presented`). |
| One signature per arming (card_nonce consumed) | **Tested** (re-present → `CardRefused`). |
| Descriptor nonce nullified on submit | **Tested** (`test_used_descriptor_cannot_be_resubmitted`). |
| Enclave holds no card key; card holds only Enclave public key | **Tested** (`test_enclave_arming_key_not_exported`) + by construction. |
| Verified-human gate (liveness AND side-button) before arming | **Tested** (`test_no_side_button_press_no_arming`, `test_no_liveness_no_arming`). |

## 4. Step Zero — the gating open questions (§1)

**Step Zero MUST pass on the target iPhone + iOS before any of this is trusted.**
It was not (and cannot be) executed here. Open questions for the device phase:

1. Does the target iOS expose **third-party ISO-7816 APDU exchange** to a
   non-Apple app (CoreNFC `NFCISO7816Tag`)? Confirm on the actual device + iOS.
2. Which **entitlements** are required (`com.apple.developer.nfc.readersession.formats`
   incl. `TAG`; `iso7816.select-identifiers` listing the applet AID), and does
   the Developer account / provisioning profile grant them?
3. **Limits:** session timeout, max APDU size, and — critically — whether the
   NFC field powers the card adequately for an **ECDSA signing operation within
   one tap**. These constrain the §4 protocol.
4. UI constraints Apple imposes (system NFC sheet) on the tap-and-hold flow.

**If Step Zero fails: STOP and report.** Do not substitute a software card.

## 5. Cryptographer review checkpoints (open issues to resolve)

1. **Enclave signature curve.** Secure Enclave keys are **P-256 only** — there is
   no Ed25519 in the Enclave. The prototype backend models arming with Ed25519
   for simplicity, but on hardware the card must verify **ECDSA-P256** armings
   (`Card2Applet` is written for secp256r1), OR the phone mints with a dedicated
   non-Enclave Ed25519 key (weaker — not Enclave-bound). **Decide and align**
   `ArmingMinter` (P-256 Enclave key) with the applet's verify curve.
2. **APDU binding & parsing.** The exact APDU layout (descriptor‖arming‖claimed
   nonce) and on-card TLV parsing are a stub in `armAndSign`; verification MUST
   precede signing and be constant-time on the nonce compare.
3. **Replay window vs `epoch`.** The descriptor binds a beacon `epoch`; decide
   whether the verifier rejects armings/descriptors past an epoch bound (ties to
   the core's epoch-cap question).
4. **Classical-on-card (prototype) vs PQC-on-card (production).** Classical EC is
   acceptable for the prototype (§7.3); PQC-on-card is the production path.
5. **Side button isolation (§5 honest boundary).** The button is part of the
   phone (Enclave-isolated), NOT a separate device. Separate-device isolation
   comes from Card 2, not the button — do not over-claim.

## 6. What is explicitly out of scope here (§7.3)

Payment-rail / settlement integration (this module produces an authorized
signature; where it settles is separate); production PQC-on-card; anything in
the token economy / minting.

## 7. Review gate (§8) — do not skip

Before any value-bearing use: (1) a qualified cryptographer / security reviewer
assesses the arming construction, card verification logic, binding, and key
handling; (2) the §11 external audit covers it against a frozen spec. This
document + the code + the tests are the package handed over. **Until then this
module is a reviewable prototype, not a payment system.**
