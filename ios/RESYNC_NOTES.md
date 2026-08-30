# iOS AtlasCore re-sync to the locked-model backend

The Swift `AtlasCore` was re-synced to the conformance'd Python backend (the
reference of record at branch head). This note records what changed, the
**verification gate**, and the **known gaps** — read it before merging to `main`.

## Verification gate (must run on the Mac)

```
cd ios/AtlasCore
swift build
swift test            # ParityTests MUST pass byte-identical to Python; unit tests green
```

Nothing in this re-sync was compiled or run — it was ported by translation from
the tested Python. `swift test` is the objective gate. Do not merge to `main`
until it passes on the Mac.

## What was ported (mirrors the Python locked-model fixes)

- **Derivation / PoLE / Params** — session key `HKDF(poleValue, lk, epochKey, prev, ctx)` (renamed from `localQRNGDraw`; HKDF input order unchanged for parity); new `Session/PoLE.swift` (physio-timed clean QRNG); `commitInterArrivalTiming=false`; ratchet clock constants.
- **Identity** — split-TSK: `reassembleSystemID` from BOTH halves, `ServerHSM`, `PseudonymTier` + `pseudonym()`, `splitUserHalfForRecovery`/`reconstructUserHalf`.
- **Presence / Cadence / Device** — presence-gated `advanceEpoch` (release → unwrap epoch key → unlock LK → derive), `advanceEpochPresent`, biological-jitter `RatchetClock`, fresh-beacon fail-closed `continuityTick` (no cache), device challenge-response, bootstrap fail-closed.
- **QRNG / Attestation** — clean LK value (`atlas/qrng/value`, timing only schedules); length-prefixed injective attestation message + `challenge`; voluntary-removal goes inert.
- **Onboarding / Tokens / Recovery** — phase gate + `EnrollmentAuthority`; `ReplayCache` (NSLock, expiry eviction) + NaN-fail-closed `verify`; holder-authority gate + PBKDF2 salted passcode + persisted attempt counter.

## Known gaps / Mac follow-ups (flagged, not faked)

1. **Provenance anti-transplant is only partially portable.** The binding helpers
   (`captureBinding`, `livenessBindLabel`/`inheritedBindLabel`) are in place, but:
   - the **inherited-proof / BBS+ real-ID stack does not exist in Swift** (`RealID/Unlinkability.swift` defers it under Step-Zero — do NOT hand-roll BBS+). So `verification_proof`, `resolve_author_under_cause`, and the `verification_inherited_ok` path have no Swift counterpart until a vetted native BBS+ binding is chosen.
   - the liveness-challenge binding is now *possible* (attestation gained `challenge`) but wiring it changes `signCapture`'s signature and its callers — deferred to the app-integration pass.
2. **Swift `Tunnel` Mode-2 freshness** wasn't part of this cluster; the demo/test
   `attest(pole)` providers use the defaulted challenge. Port the fresh-challenge
   handshake when wiring Mode-2 on device.
3. **Deviations to confirm under `swift test`:** `Child.context` widened to
   `String`; `IdentityTree.build` gained defaulted `rotation`/`serverHSM`;
   `RecoveryEnrolment` is now a `class` (reference semantics for the persisted
   attempt counter); `Recovery` uses `CommonCrypto` PBKDF2 (Apple SDK only — not
   Linux swift-crypto); `RatchetClock`/`pseudonym` are `throws`.
4. **Hardware-gated (unchanged):** real Secure Enclave / HSM residency, App
   Attest anchor, R10 BLE liveness, camera/LiDAR PAD — see `../HARDWARE_TESTING.md`.

## BINDING REQUIREMENTS — live-provenance binding (Code Spec Priority 1 / T-25b)

The Python reference now binds attribution VALIDITY, non-optionally, to the live
provenance of its moment (`atlas/provenance/live_binding.py`,
`test_provenance_live_binding.py`, all green). Any Swift port of `signCapture` /
`verifyProvenance` **MUST** reproduce these four bindings byte-identically (they
are parity-critical — the witness signature is over hashed inputs):

1. **1.1 current LK → recipient-verifiable.** The witness signing key is
   `keypairFromSeed(H("atlas/lk-witness", lk, epochId))`. The server publishes
   only the PUBLIC half per epoch to an append-only `PublicWitnessRegistry`
   (prev-chained: `H("atlas/witness-chain", head, epochId, pub.encode())`). A
   recipient verifies the witness signature against that public half **without
   the LK**. Do NOT input-bind the raw LK (breaks recipient verifiability).
2. **1.4 live session key.** `sessionCommit = H("atlas/prov/session-commit",
   sessionKey, contentHash)` is folded into the signed core; opaque to a recipient
   but tying the attribution to a real live session.
3. **1.3 epoch position (no backdating).** The witness key is epoch-specific
   (LK is per-epoch, QRNG-valued); the append-only registry fixes the "when". A
   binding made at epoch A verifies only against A's published public half.
4. **1.2 author presence (self-incrimination).** `attributionCore =
   H("atlas/prov/attribution-core", contentHash, epochId, authorshipHandle,
   sessionCommit)` binds the authorship handle; the authorship signature means
   forging ANOTHER identity is a detectable mismatch (the key hashes to the
   producer, not the claimed victim).

The witness keypair is the **hybrid PQC** signature (ML-DSA + Ed25519), so a
quantum BBS+ forger still cannot forge the binding without the LK.

**Bundle/verdict wiring:** `ProvenanceBundle` gains `liveBinding`
(`sessionCommit`, `witnessSig`); `transcript()` appends
`H("lb", sessionCommit, witnessSig)`; `verifyProvenance` requires a
`witnessRegistry` arg and computes `liveProvenanceOk`; `accountable` becomes
`all([...existing, liveProvenanceOk])`. Because these change the `signCapture` /
`verifyProvenance` signatures, this rides the same app-integration pass as gap-1
above (BBS+ real-ID stack still deferred; live-binding does NOT depend on BBS+
and can land first).

**Honest residual (mirror in any UI copy):** this contains remote /
harvest-then-forge, NOT a present insider — the LK is cohort-shared per epoch.
Do not label the result "unforgeable"; forgery is contained to the
coercion/endpoint floor, and insider forgery of *others* is self-incriminating.

## Swift gap — local duress slice (Code Spec Priority 3)

`atlas/session/duress_vault.py` (`PanicVault`: panic-code decoy + zeroize-on-
suspicion) has **no Swift counterpart yet**. It is pure AES-GCM + HKDF over the
existing `Vault`/`Presence` primitives, so the port is mechanical, but it changes
no existing signatures and can land in the app-integration pass. On device the
seal/release is the **real Secure Enclave** (not the Python AEAD model) and the
zeroize is the Enclave dropping the key (plus hardware anti-tamper, out of scope).
No parity vector is needed for the decoy/zeroize control flow (it is behavioural,
not a KAT); the underlying HKDF/AEAD glue is already pinned.

## Swift port — swappable SignalSource (ambient iPhone PoC)

`Session/SignalSource.swift` ports `backend/atlas/session/signal_source.py`:
`LiveSignalSample`, the `SignalSource` protocol, `RingSignalSource` (deferred
swap point, throws `.unavailable`), `ClosureSignalSource` (closure-backed so the
core does not depend on CoreMotion/AVFoundation — the app injects the real fused
reader), and `timedRatchetStep` (source-agnostic driver). `SignalSourceTests.swift`
mirrors the Python invariant tests (value-independence, presence gate = liveness,
timing = first byte, ring-deferred, loudly-simulated). **Unrun on Linux** — Mac
`swift test` is the gate. The presence/timing derivation must stay byte-identical
to Python (empty/flatlined window -> not present; timing = window.prefix(1)); it
is behavioural (no KDF), so no parity KAT is needed. The real ambient sensor
fusion lives in the app target (AtlasApp/Ambient), NOT the pure core.

## Swift port — PanicVault + the ambient iPhone app layer

- `Session/DuressVault.swift` ports `PanicVault` (panic-code decoy + zeroize).
  Mechanical AES/HKDF over `Vault`; unrun on Linux, Mac `swift test` is the gate.
  Production sealing is the real Secure Enclave (not the AES model).
- `AtlasApp/` gained the ambient PoC layer (hardware-bound app target, NOT part
  of `swift test`; validated by the Xcode ⌘R run per AMBIENT_POC_RUNBOOK.md):
  `Config/AtlasFlags.swift` (flags + honesty banner), `Ambient/AmbientSensorSource
  .swift` (real CoreMotion/AVAudio fusion → TIMING/GATING only, never a value),
  `Enrolment/EnrollmentCeremony.swift` (Face ID + password + button + forensic
  window), `Session/AtlasRuntime.swift` (wires the full pipeline; INTEGRATION
  SEAM: the model Device self-generates its presence secret — production merges
  it with the SE-sealed enrolment secret), `Session/AtlasTunnelClient.swift`
  (real ML-KEM handshake; HTTP transport to the Mac backend is the seam),
  `UI/AmbientPoCView.swift` (+ ContentView tab), Info.plist mic/motion usage.
- Live-provenance attribution binding (Priority-1) remains DEFERRED in Swift; the
  runtime marks attribution DEFERRED rather than faking it.

## Swift ports — C8 forensic window + C9 secure vault

- `Session/Forensic.swift` ports `atlas/session/forensic.py`: `AlarmCause`,
  `ForensicHeader`/`ForensicChunk`, `ForensicWindow.open` (escape-first: emits
  header + first burst immediately), `capture` (sealed, hash-chained, anchored,
  no plaintext buffer), `openForensicWindow` (recovery-key verify + decrypt).
  Sealed to the user's recovery KEM key; host-blind; tamper-evident.
- `Session/SecureVaultStore.swift` ports `atlas/session/secure_vault.py`:
  presence-gated (PoLE operating + Enclave biometric match) put/get, per-item
  provenance stamp (author-signed, binds content+epoch), `BackupChoice`
  (.phoneOnly / .nonCustodial KEM-wrapped to recovery, host-unreadable).
- Unrun on Linux — Mac `swift test` is the gate. Python is reference-of-record
  (test_forensic.py 7, test_secure_vault.py 7, all green).

### App-wiring spec (the remaining, hardware-bound piece — app target, ⌘R gate)
- **C8 alarm → forensic:** any alarm (panic code/phrase, improper BLE
  disconnect, suspicious lifecycle, failed-recovery) calls
  `ForensicWindow.open(cause:recoveryPub:initialCapture:beacon:sink:)`. The
  `initialCapture` is a fresh multimodal burst (camera+mic); the `sink` ships
  each sealed artifact OFF-DEVICE immediately to the non-custodial store (reuse
  the blind-relay/`AtlasRelayClient` transport). NO local buffer. Escape-first.
- **C9 vault:** a `SecureVaultStore` per user; `put/get` gated by the same
  presence path as the ratchet. iOS **Files / document-provider** integration so
  other apps save INTO the vault; mark storage **non-purgeable** so iOS doesn't
  reclaim it. Backup toggle in UI (phone-only vs non-custodial).
- **Honest boundary (put in UI copy):** cryptographic unreadability ("even Apple
  can't read it"), NOT physical exclusion ("Apple can't reach the storage").
