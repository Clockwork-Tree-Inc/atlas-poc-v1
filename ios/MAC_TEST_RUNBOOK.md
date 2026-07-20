# Mac Test Runbook — collapsing the Swift gate

> ✅ **GATE CLEARED (2026-07-07, macOS 26 / Xcode iOS 26.5 SDK).** `AtlasCore`
> builds and `swift test` passes on a real Mac. The SDK adaptations that were
> required (already committed) — so the next machine is turnkey:
> - **Platform pin:** use the STRING form `.iOS("26.0"), .macOS("26.0")` in
>   `Package.swift` (the `.v26` enum case does not exist at swift-tools-version 6.0).
> - **PQC random generators throw:** `MLKEM768.PrivateKey()` / `MLDSA65.PrivateKey()`
>   now `throws` → wrapped in `try!` in `generateKeypair`/`HybridSign.generate`/
>   `Recognition.hybridContribution` (random keygen only fails catastrophically).
> - **Seeded ML-DSA:** `MLDSA65.PrivateKey(seedRepresentation:)` now requires
>   `publicKey:` → pass `nil`.
> - **Testing destination:** run on **My Mac** (package unit tests can't host on a
>   physical device).

**Goal:** turn the Swift `AtlasCore` from *translated-but-unrun* into *verified*.
Everything Swift-side (the original port, the Priority-1 binding requirements, the
Priority-2 parity assertions, the Priority-3 duress port) has only ever been
checked by translation against the Python reference. The single action that
collapses that uncertainty is **`swift test` on a Mac**. This runbook makes that
one clean pass instead of a debugging expedition.

The Python side is the reference-of-record and is already green (175 tests). The
Swift side must reproduce the pinned parity vectors **byte-for-byte**; that is the
objective gate.

---

## 0. What you need

| Requirement | Why | Note |
|---|---|---|
| A **Mac** (Apple silicon or Intel) | CryptoKit + Swift toolchain | Linux cannot build this |
| **Xcode 16+** (or matching Command Line Tools) | Swift 6 toolchain (`swift-tools-version: 6.0`) | `xcode-select --install` for CLT only |
| An **SDK that ships CryptoKit PQC** (ML-KEM-768 / ML-DSA-65) | the hybrid KEM/signature use Apple's PQC types | **This is the #1 thing that can block the build — see §Known-blockers** |
| Python 3.11+ (optional, for Part A) | re-run the reference + confirm vectors are fresh | already validated on Linux |

> The `AtlasCore` **package** builds and tests *without* Xcode's app target — it
> is pure Swift + CryptoKit. The `../AtlasApp` Xcode project (CoreBluetooth R10,
> Secure Enclave, App Attest, camera, SwiftUI) is a **separate** hardware-bound
> build and is **not** part of this gate.

---

## 1. One-command path (recommended)

From the repo root:

```bash
./run_all_tests.sh          # Part A (Python) then Part B (Swift), if both present
```

- On Linux it runs Part A and prints "swift toolchain not found — skipping".
- On a Mac it runs both. Part A also **regenerates the parity vectors and fails if
  they drifted** — so you never test Swift against stale vectors.
- Sub-commands: `./run_all_tests.sh backend` or `./run_all_tests.sh swift`.

If `run_all_tests.sh` ends with **ALL CLEAR**, the gate is collapsed. If not, use
the step-by-step below to locate the failure, then §Interpreting-failures.

---

## 2. Step-by-step (manual path)

### Step 1 — get the code and confirm the toolchain
```bash
git clone <repo> Atlas-PoC          # or: git fetch && git checkout integrate-poc
cd Atlas-PoC
swift --version                      # expect Swift 6.x
xcodebuild -version                  # expect Xcode 16+
```

### Step 2 — (optional but recommended) refresh + verify the parity vectors
The Swift `ParityTests` read `ios/AtlasCore/Tests/AtlasCoreTests/Resources/parity_vectors.json`.
Make sure it matches the current Python core:
```bash
cd backend
python3 -m pip install -r requirements.txt      # first time only
python3 -m pytest -q                             # expect: 175 passed
python3 -m tools.gen_parity_vectors              # rewrites both copies of the JSON
cd ..
git diff --stat -- backend/parity ios/AtlasCore/Tests/AtlasCoreTests/Resources
#   no diff  = Swift is testing against current vectors (good)
#   a diff   = commit it first; the committed JSON was stale
```

### Step 3 — build the Swift core
```bash
cd ios/AtlasCore
swift build
```
If this fails, it is **almost certainly the CryptoKit PQC symbols** — go to
§Known-blockers, apply the one-line adaptation, and re-run.

### Step 4 — run the tests
```bash
swift test                     # all targets
# or focus one area while iterating:
swift test --filter ParityTests
swift test --filter AtlasCoreTests
swift test --filter ProvenanceTests
```
Expect **34 test methods** across four files:
- `AtlasCoreTests` (8) — crypto/identity/recovery/liveness/recognition round-trips
- `ProvenanceTests` (3) — PAD + capstone sign/verify
- `ParityTests` (18) — the cross-impl byte-for-byte gate (incl. the 3
  Priority-2 categories `testIdentityTreeSplitTSK`/`testPresenceUnwrapChain`/
  `testLiveProvenanceBinding`, plus `testXWingCombine` — pins the hybrid-KEM
  combiner transcript so the phone↔Mac tunnel key can't silently diverge)
- `SignalSourceTests` (5) — the ambient signal-source value/timing invariant
  (value-independence, presence gate, timing=first byte, ring-deferred, simulated)

**Green across all three = the Swift stack is verified against the Python reference.**

---

## 3. Known-blockers (expected on the first run) {#known-blockers}

These are flagged in the source (`Crypto/HybridKEM.swift`, `Crypto/HybridSign.swift`
carry `VERIFY-AGAINST-SDK` notes). None is a design defect — each is a "confirm the
symbol against the SDK you actually have."

| # | Symptom at `swift build` | Cause | Fix |
|---|---|---|---|
| B1 | `cannot find 'MLKEM768' / 'MLDSA65' in scope` | Your SDK's CryptoKit predates Apple's PQC types, or names them differently | Update to the Xcode/SDK that ships CryptoKit PQC; **or** add the `swift-crypto` package and import its ML-KEM/ML-DSA; **or** map to the exact type names in your SDK. Keep the X-Wing HKDF combiner (`Params.labelXWing`) identical so both ends still agree. |
| B2 | `incorrect argument label` on `MLDSA65.PrivateKey(seedRepresentation:)` or `MLKEM768.PublicKey(rawRepresentation:)` | Initializer label drift across SDK betas | Adjust the label to your SDK (`seed:` / `rawRepresentation:` / `dataRepresentation:`). The **bytes** must be identical; only the Swift label changes. |
| B3 | Platform-availability error (`… is only available in macOS 26 / iOS 26`) | PQC APIs need a newer deployment target than `Package.swift` pins (iOS 18 / macOS 15) | Bump the `platforms:` line in `Package.swift` to the version your SDK requires for PQC, then rebuild. |
| B4 | `swift test` warns "found N unhandled files" for the test target | A stray non-`.swift` file in a source dir | Harmless. If you want it clean, delete the stray file (e.g. an accidental `.pytest_cache/`). |

> **If PQC symbols block you and you only want to prove the Atlas glue today:**
> the parity vectors that matter for identity/presence/provenance (`sha3_256`,
> `hkdf`, `hkdf_combine`, `ratchet`, `session_key_decoupled`, `identity_tree_split_tsk`,
> `presence_unwrap_chain`, `live_provenance_binding`, `pad`, `ledger`, `token_mac`,
> `capture_metadata_canonical`) use **only SHA-3/HKDF/AES-GCM/X25519 — no PQC**.
> Only `recognition`/tunnel and the hybrid KEM/sign round-trips touch PQC. So even
> if B1–B3 delay the PQC types, the **library-of-truths glue can be gated first**
> by fixing compilation of the non-PQC path.

---

## 4. Interpreting failures {#interpreting-failures}

Once it **compiles**, a `swift test` failure is a genuine cross-impl divergence.
Read the failing assertion — every parity test names the byte that disagreed.

| Failing test | What diverged | Where to look |
|---|---|---|
| `testSHA3` / `testHKDF*` | the base hash/KDF glue | `Crypto/Primitives.swift`, `Crypto/SHA3.swift` — chunk concatenation order, HKDF salt convention |
| `testSessionKey` | session-key HKDF input order/labels | `Keys/Derivation.swift` — must be `[lk, epochKey, poleValue, prevKey, ctx]`, info `LABEL_SESSION` |
| `testIdentityTreeSplitTSK` | split-TSK derivation | `Keys/Identity.swift` — `tskHalves` info labels, `reassembleSystemID`, child/pseudonym info strings |
| `testPresenceUnwrapChain` | presence unwrap/lk-key derivation or AEAD | `Session/Presence.swift` — info `atlas/epoch-unwrap\|`+epochID, `atlas/lk-unlock\|`+epochID, AADs |
| `testLiveProvenanceBinding` | the Priority-1 witness cores | the three `Primitives.H(...)` cores must match `atlas/lk-witness`, `atlas/prov/session-commit`, `atlas/prov/attribution-core` (order-sensitive) |
| `testRecognition` / `testTunnelEvolve` | X25519 ephemeral derivation | `Session/Recognition.swift` |
| `ProvenanceTests.*` | PAD math or capstone transcript | `Provenance/Provenance.swift` |

**Fix on the Swift side, not by editing the vectors.** The vectors are the contract
the Python reference already satisfies; a divergence means the Swift port's glue is
off by a label/order/prefix. (The one exception: if you intentionally change a
derivation in Python, re-run `gen_parity_vectors.py`, commit both JSON copies, then
re-run Swift.)

---

## 5. Consolidated Mac-clearance checklist

Tick these; when all are ticked the accumulated Swift pile is collapsed.

- [ ] `swift --version` = 6.x, `xcodebuild -version` = 16+ (macOS 26 ships the
      CryptoKit PQC symbols, so the KEM/sign path should compile too)
- [ ] Part A green on this machine (or trust the committed 193-pass) and
      `git diff` shows **no** parity-vector drift
- [ ] `swift build` succeeds (after any B1–B3 SDK-symbol adaptation)
- [ ] `swift test --filter ParityTests` → **18 green** (byte-for-byte gate, incl.
      the 3 Priority-2 categories + `testXWingCombine`)
- [ ] `swift test --filter AtlasCoreTests` → **8 green**
- [ ] `swift test --filter ProvenanceTests` → **3 green**
- [ ] `swift test --filter SignalSourceTests` → **5 green** (ambient invariant)
- [ ] Full `swift test` green (**34 methods**)
- [ ] If any SDK adaptation was made (B1–B3), commit it with a note of the exact
      symbol/label your SDK required (so the next machine is turnkey)

### Known deviations to expect/fix on the Mac (flagged during translation)
These are Swift-only adjustments already noted in `RESYNC_NOTES.md`; confirm each
compiles/passes on your SDK:
- **CommonCrypto PBKDF2** (`Recovery`) — Apple SDK only (not Linux swift-crypto);
  should just work on macOS.
- **`Child.context` widened to `String`** and **`IdentityTree.build` defaulted
  `rotation`/`serverHSM`** — confirm call sites.
- **`RecoveryEnrolment` is a `class`** (reference semantics for the persisted
  attempt counter) — confirm no value-copy assumptions.
- **`throws` additions** (`RatchetClock`/`pseudonym`) — confirm `try` at call sites.
- **X-Wing KEM combiner** now folds `mlkemCT` (fixed this session) — `testXWingCombine`
  guards it; if it fails, the fix didn't apply.
- **New files to compile:** `Session/SignalSource.swift`, `Session/DuressVault.swift`
  (core); the `AtlasApp/` ambient + relay layer (app target, built via ⌘R not
  `swift test`).

### Still deferred *after* this run (by design, not blockers)
- **BBS+ verification-inheritance in Swift** — Step-Zero: do NOT hand-roll; wire a
  vetted native (Rust-FFI) engine. `RealID/Unlinkability.swift` specifies it. The
  Priority-1 live-binding does **not** depend on BBS+ and gates independently.
- **Swift port of the Priority-1 `live_binding` module and the Priority-3
  `PanicVault`** — mechanical, no signature changes; land in the app-integration
  pass. The parity cores for live-binding are already pinned inline so the port
  has a compiled contract.
- **`AtlasApp` (Xcode) build + R10 ring hardware** — the separate device/liveness
  validation milestone (TRL 4 → 5), independent of this package gate.
