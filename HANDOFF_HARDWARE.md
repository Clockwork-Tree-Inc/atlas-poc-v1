# Handoff — hardware factors (device wiring)

The reference-of-record for all three hardware factors is built, tested, and pushed
(Python + Swift parity). What remains is **device-only wiring** — the physical
SDKs/IO that can't run in the cloud. This is one batch so you can wire them in
sequence and report each back for review against a finished reference.

**Discipline:** Python is reference-of-record (285 passed). Fix Swift to match the
reference if a parity test fails; never weaken a test. Stay on
`integrate-poc`.

## The gate (run first)

```bash
cd ios/AtlasCore && swift build && swift test
```
New parity suites that must pass: `RingTests`, `HardwareFactorTests` (+ the earlier
`EntropyTests`, `ChangeDetectionTests`, `ConversationTests`, `MediaVaultTests`,
`LiveLKTests`). Parity vectors pinned: `ring_h_i=0.95928`, `ring_s_i=0.839088`,
ring `timing=203`, high-stakes `message=huoYWdon3GuOJQiC3GulEA4vSarE1HDo+v3WCb73SdI=`.

---

## 1. Ring (R10) — BLE → `RingSignalSource` sampler

The ring is fully wired in `AtlasCore` (`RingSignalSource`, `GBSS.ringHI/ringSI`).
The only device piece: read the real R10 over BLE into `SensorSample`s and feed the
sampler.

- Build on the existing `AtlasApp/Ring/R10BLEClient.swift` + `R10Protocol.swift`.
- Discover the R10's GATT characteristics for **heart rate + HRV** (often the
  standard Heart Rate Service `0x180D`, HRV via R-R intervals in the measurement
  characteristic) and its **accelerometer** stream (vendor characteristic — sniff
  with the ring's app / LightBlue if undocumented).
- Map each reading to `SensorSample(hr:hrvMS:spo2:accelMag:)` and hand it to
  `RingSignalSource(sampler: { latestSample })`.
- Then in `AtlasRuntime`, when the ring is connected, set
  `AtlasFlags.signalSource = .ring` — the pipeline swaps with no other change
  (source-agnostic), and the PoLE now gates on a real pulse; `h_i` + `s_i` come from
  the wrist. A removed ring (near-zero accel) fails closed automatically.

**Report:** does a worn ring show `present=true` / operate, and does taking it off
gate the ratchet closed?

---

## 2. The intent gesture (the "side-button press") — per-platform

The high-stakes primitive is the **intent gesture**: a deliberate, hardware-attested
"yes, do THIS, now", bound to one action. It is distinct from ambient/ring liveness
(who / alive). `AtlasCore/Keys/HardwareKey.swift` models it protocol-agnostically
(`HighStakesRequest.message`, `verifyHighStakes`); `fingerprintMatched` is the abstract
"the live human physically confirmed." The *device that produces the gesture is
swappable per platform* — the auth primitive never changes.

### iPhone: Face ID per-action confirm (SHIPPING — the default)

The literal iPhone side-button double-click is **PassKit/Apple Pay only** — a third
party cannot summon it for a general authorization. The YubiKey **Bio has no NFC**, and
iOS FIDO2 is NFC/Lightning only, so the Bio **cannot drive the iPhone** (enrol witness
step is suspended, commit `c4c3ddc`). The intent gesture on the phone is therefore a
**per-action Face ID / Touch ID confirm** whose prompt names the exact action:

- `AtlasApp/Auth/IntentGesture.swift` → `IntentGesture.confirm(action:)`
  (`LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)`, biometry-only,
  fail-closed on cancel/lockout/no-biometry).
- Wired at the marquee high-stakes action — **Recovery** (`RecoveryView.recover`): the
  userHalf is never released without a live confirm. Adopt the same call at any other
  high-stakes site (vault open, disenrol, a future payment authorize).
- **Follow-up to make the *signature* itself gesture-bound** (so a bare boolean can't
  stand in): promote the step-up signer to a biometry-gated
  `SecureEnclave.P256.Signing.PrivateKey` (access control `.privateKeyUsage +
  .biometryCurrentSet`; see `Enclave/SecureEnclaveStore.loadOrCreateEnclaveSigningKey`),
  register ITS public key as the step-up key, and add a **P-256 step-up parity path** to
  `verifyHighStakes` in AtlasCore (Python + Swift + a compiled `swift test`). Until then
  Face ID is the real *gesture*; the signer stays modelled.

### Desktop / a future NFC key: YubiKit

The Bio is a great desktop factor (macOS/Windows). If you add an **NFC-capable** key
(5C NFC / Security Key NFC) it can also serve as a detached intent gesture on the phone:

- Add the **YubiKit** SPM package; build `HighStakesRequest(action:context:challenge:)`,
  take `.message()`, sign via **PIV** (slot key, Ed25519/ECDSA) or **FIDO2** (assertion).
  The touch/tap IS the gesture (FIDO2 user-presence).
- Verify with `verifyHighStakes(publicKey, request, signature)` (swap the matching
  verify for ECDSA/FIDO2; keep the message binding identical so it stays anti-replay).
- Register each key's public key at enrolment; optionally hold a recovery Shamir share
  via `holdRecoveryShare` (factor 3).

### Payments

Payments are one high-stakes ACTION, gated by the same gesture — **not** the side button
(iOS blocks the rail for third parties). Build `HighStakesRequest(action: "payment",
context: H("atlas/pay-intent", descriptor.canonical), challenge: cardNonce)`, gate it
with the platform gesture (Face ID on iPhone), and mint the IntentToken from the verified
result (Python reference: `payment/yubikey_intent.py`). No side button anywhere.

**Report:** does a high-stakes action (incl. recovery / a payment) require the live
per-action gesture, does cancelling Face ID fail closed, and does a gesture for one
action fail to authorize another?

---

## 3. USB DualDrive — file IO → `writeShareToUSB` / `readShareFromUSB`

`AtlasCore/Keys/USBRecovery.swift` does the crypto (KEM-wrap the recovery share).
The device piece is just reading/writing the opaque blob on the Lexar D40e.

- The D40e is USB-C — it mounts via the **Files app**; access it with
  `UIDocumentPickerViewController` (or a `FileProvider`/security-scoped URL).
- On enrolment: take the recovery `share_card` vertex, call
  `writeShareToUSB(share, recoveryPub:)`, and write `blob.toBytes()` to a file on
  the drive (e.g. `atlas-recovery.share`).
- On recovery: read the file, `USBRecoveryBlob.fromBytes(...)`,
  `readShareFromUSB(blob, recoveryKP:)`, then `Shamir.combine([usbShare, otherVertex])`
  to rebuild the TSK. One share alone can't — needs 2-of-3.
- The JSON byte format matches the Python reference, so a blob is portable
  phone↔Mac.

**Report:** does the drive round-trip (write on enrol, read on recover), is a lost
drive opaque (no plaintext share in the file), and does a wrong key fail closed?

---

## Role separation (holds across all three)

- **Ring** — liveness sensor, holds **no secrets** (removal → fail-closed).
- **YubiKey** — high-stakes secret-holder (signs actions, may hold a share).
- **USB** — recovery secret-holder (encrypted share; lost drive is opaque).

The always-worn, easily-lost thing (ring) carries nothing secret; the deliberate,
rarely-touched things (YubiKey, USB) carry the secrets.
