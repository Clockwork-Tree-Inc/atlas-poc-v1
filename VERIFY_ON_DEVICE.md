# VERIFY_ON_DEVICE.md — closing the gaps on the running system

The security review's open gaps are almost all "can't be tested from the Linux
reference box." They close by **running the two-phone setup + on-device tests on the
Mac**. This is the checklist that produces the real evidence — run each, paste the
actual result back so we replace every "untested here" with a number.

Reference side is green: **329 Python tests**, **21 parity vectors** (now incl.
`recovery_selector`, forensic `signal_digest` + `event_chain`). Those vectors are the
byte-exact contract the Swift port must satisfy.

## 1. Cross-language byte parity  (gap: interop)
```
cd ios/AtlasCore && swift build && swift test
```
- Report the full `swift test` summary. The load-bearing suite is **`ParityVectorTests`**
  (asserts `Resources/parity_vectors.json` — the SAME file Python asserts). Green here =
  the Swift glue is byte-identical to the Python reference.
- Also report: `LiveLKTests, ConversationTests, MediaVaultTests, ChangeDetectionTests,
  EntropyTests, RingTests, HardwareFactorTests, AuthTests`.
- **This is THE gap-closer** — parity vectors exist; this run proves the Swift side meets
  them.

## 2. PQC runtime interop  (gap: real PQC backends)
The static vectors deliberately skip ML-KEM/ML-DSA (randomized). Do the **runtime**
check the vectors can't: **encapsulate on phone A → decapsulate on the Mac** (and a
signature made on device → verified in Python). Confirm the shared secret matches and
the signature verifies across the language boundary. Report pass/fail + which backend
(CryptoKit vs liboqs vs the pure-Python reference).

## 3. Device attestation  (gap: attestation is a boolean stub)
Exercise **real App Attest / DeviceCheck / Secure Enclave** on a phone: produce an
attestation/assertion and verify it. Confirm the enrol/recovery gate consumes the REAL
attestation, not the boolean stub. Report: does a genuine device pass and a
missing/invalid attestation fail closed?

## 4. Ring liveness  (gap: liveness on synthetic streams only)
With the R10 on a wrist: confirm real PPG → **coherent = live** (ratchet operates) and
**removed / flat-HRV spoof = ABSENT → fail-closed**. Report the live vs removed behavior.
(Population-scale Sybil / anti-farm is out of scope — needs a campus pilot, not this box.)

## 5. Two-phone live run  (end-to-end on the running system)
```
cd backend && python -m atlas.net.node_server --host 0.0.0.0 --port 8787
```
Point both phones at `http://<mac-lan-ip>:8787`. Confirm: both come online → co-derived
LK (matching prefix) → forward-secret messages through the BLIND relay. (Already ran ✓ —
re-run to confirm still green after the recent commits.)

## 6. New modules on device  (needs the Swift ports first)
`recovery_anchor` and `forensic_ledger` are reference-of-record + parity-pinned but **not
yet ported to Swift**. Once ported (`AtlasCore/RealID/RecoveryAnchor.swift`,
`Session/ForensicLedger.swift`), their `ParityVectorTests` rows must match, then run the
on-device flows:
- **Recovery anchor:** enrol (name + password + face + Bio witness on the Mac) → total-loss
  ceremony → fail-closed on wrong biometric / absent recovery-person.
- **Forensic ledger:** every login / high-stakes decision writes a vault-sealed event;
  tamper (alter/drop) breaks `verify()`; a sudden liveness loss classifies SUSPICIOUS.

## 7. Sybil / farm resistance — three tiers

Sybil resistance is a COST claim: "one live human = one identity." It closes across three
tiers, cheapest to realest.

**Tier A — quantitative sim (no testers, runs now):**
```
cd backend && python -m atlas.sim.sybil
```
Gates farm strategies against the REAL liveness operators on the real 24 subjects.
Expected: **replay → cost 1.0 live-session/identity (no amplification), synthetic → ∞
(0 valid), real humans → 1.0 (linear floor).** The result: farming N identities costs N
real live humans.

**Tier B — two-phone harness (on the running system):** with both phones + rings, try to
*beat* the floor and confirm each fails:
- **Same human, two identities:** enrol one person on phone A, then try to enrol the SAME
  person again → the live binding should not mint a second independent identity for free.
- **Replay-to-clone:** capture phone A's ambient/ring feed, replay it to stand up a second
  identity on phone B → must **fail-closed** (change-based + min-entropy + ring coherence).
- **Report:** did any path mint an identity for less than one distinct live human-session?

**Tier C — recruited pilot (post online):** the real accept/reject rates + real farm
economics. REQUIRES an *adversarial track* (testers paid to try to farm/spoof, not just
normal users) and consent/privacy handling for biometric data. Validates Tier A's numbers.

## What CANNOT be closed by running (be honest)
- **Ratchet non-invertibility** — a standard HKDF/SHA one-wayness assumption; not testable.
- **Constant-time / side-channel** — pure-Python isn't; production uses CryptoKit
  (constant-time). Out of scope for the bench PoC.
- **Population-scale Sybil / anti-farm** — needs a real multi-user pilot.
- These stay on the "independent audit / pilot" list, not the "we forgot to test it" list.

## Report format
For each of §1–§6: the command run, the actual result (test summary / pass-fail), and any
device tuning needed. That turns the gap table from "untested here" into "verified on
<device>, <date>."
