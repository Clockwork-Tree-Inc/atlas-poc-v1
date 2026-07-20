# Atlas PoC — iOS / Swift

The on-device side of the Atlas PoC. **This is source written for the Mac** — it
cannot be compiled or run in the cloud build environment (no Xcode, no Swift
toolchain, no devices). It is the Swift sibling of `backend/atlas` and is
structured so the pure-Swift protocol core builds and `swift test`s on the Mac,
while the hardware-bound surfaces live in an Xcode app target.

## Layout

```
ios/
├── AtlasCore/                 SwiftPM package — pure Swift + CryptoKit protocol core
│   ├── Package.swift
│   ├── Sources/AtlasCore/
│   │   ├── Params.swift                §3.2 frozen decisions (mirror of params.py)
│   │   ├── Crypto/                     primitives, hybrid KEM/sign, Shamir
│   │   ├── Beacon/                     drand client + offline beacon, presence QRNG
│   │   ├── Keys/                       derivation+ratchet, tokens, identity, recovery
│   │   ├── Liveness/                   Bayesian gate, synthetic streams, attestation
│   │   ├── Session/                    device, recognition/tunnel, vault, two modes
│   │   └── Provenance/                 ledger, PAD (depth/moiré), capture sign/verify (§8)
│   └── Tests/AtlasCoreTests/           XCTest mirror of the Python suite
└── AtlasApp/                  Xcode app sources (CoreBluetooth / Secure Enclave / UI)
    ├── AtlasPoCApp.swift
    ├── Info.plist                      BLE / camera / Face ID usage strings
    ├── Ring/                           R10 wire protocol + CoreBluetooth driver (§1.2)
    ├── Enclave/                        Secure Enclave key store + App Attest (§0.3, §6)
    ├── Enrolment/                      co-motion ring-lock (accelerometer, §6)
    ├── Capture/                        AVFoundation earliest-frame + LiDAR depth (§8.2)
    └── UI/                             SwiftUI shell: M1 crypto, M2 liveness
```

`AtlasApp` depends on `AtlasCore`. The split mirrors the backend: the protocol
core is portable and testable; the device/BLE/enclave/camera surfaces are not.

## Build on the Mac

### 1. Protocol core (no devices needed)

```bash
cd ios/AtlasCore
swift build
swift test            # XCTest mirror of the Python core tests
```

### 2. The app (Xcode + a 17 Pro Max)

There is **no `.xcodeproj` checked in** (a hand-authored pbxproj is fragile).
Create the app target in Xcode and add these sources:

1. Xcode → New Project → iOS App → SwiftUI, name **AtlasPoC**.
2. File → Add Package Dependencies → Add Local… → select `ios/AtlasCore`.
3. Add the files under `ios/AtlasApp/` to the target (or drag the folder in).
4. Use `ios/AtlasApp/Info.plist` (or copy its keys into the target's Info).
5. Signing & Capabilities:
   - set your **Team** (Apple Developer account),
   - add **App Attest** capability,
   - confirm **Background Modes → Uses Bluetooth LE accessories** if you want
     the ring stream to survive backgrounding.
6. Set the deployment target to your installed iOS (the PQC + Secure Enclave
   APIs require recent SDKs — see the note below). Confirm Xcode targets the
   device's iOS version before building (§1.4).
7. Build & run on the 17 Pro Max. Ring BLE is exercised on the phone, never the
   Mac (§1.2).

## VERIFY-AGAINST-SDK (important)

A few APIs are recent enough that the exact symbol names must be confirmed
against your installed SDK — they are flagged inline:

- **PQC in CryptoKit** (`MLKEM768`, `MLDSA65`, optionally `XWingMLKEM768X25519`)
  — `Crypto/HybridKEM.swift`, `Crypto/HybridSign.swift`. If you adopt Apple's
  `XWingMLKEM768X25519`, also switch the Python core to the RFC X-Wing combiner
  so both ends still interoperate. As written, the hybrid is an *X-Wing-style*
  HKDF combiner, byte-identical across the Swift and Python cores.
- **SPHINCS+ / SLH-DSA** — `Crypto/HybridSign.swift` exposes a `SphincsProvider`
  seam. Back it with CryptoKit SLH-DSA (when present), a vendored SPHINCS+, or
  the production on-card/HSM root. The app ships a clearly-marked
  `PlaceholderSphincs` so the shell runs; **replace it before any security claim.**
- **SHA-3** — `Crypto/Primitives.swift`. If `SHA3_256` is unavailable on your
  SDK, substitute SHA-256 for `H()` on **both** ends (the spec allows SHA-3/SHA-2);
  the two cores must agree to interoperate across the wire.

## Concurrency note

`Ring/R10BLEClient.swift` is `@MainActor` (it drives `@Published` UI state) and
runs CoreBluetooth on the main queue, so its delegate callbacks are main-isolated.
New Xcode app projects default to the **Swift 5 language mode**, where this
compiles cleanly. If you opt the app target into the Swift 6 language mode, mark
the `CBCentralManagerDelegate` / `CBPeripheralDelegate` methods `nonisolated` and
hop to the main actor for the `@Published` writes. `AtlasCore` itself is
concurrency-clean under Swift 6.

## What runs where

| Milestone | Runs on | Notes |
|-----------|---------|-------|
| M1 — encrypted text A→B, forward secrecy, two modes | phone (in-process) or Mac (`swift test`) | `UI/Milestone1View.swift` mirrors the Python demo |
| M2 — R10 BLE capture + liveness gate + containment | phone only | needs a paired Colmi R10 |
| M3 — enrolment ritual + co-motion ring-lock | phone only | `Enrolment/CoMotionRingLock.swift` |
| M4 — recovery (card/in-person/recovery-child) | core on phone/Mac; card path needs the JavaCard | |
| M5 — depth-checked capture + provenance | core on phone/Mac; capture phone only | provenance+PAD core in `AtlasCore/Provenance`; camera/LiDAR in `AtlasApp/Capture` |
| M6 — verified-human-only viewing | core ready; on-device wiring on phone | `Session/Tunnel.swift` Mode 2 |

The Colmi R10 GATT UUIDs, 16-byte packet format, checksum, and the real-time
streaming command (not the ~20-minute passive log) are implemented in
`Ring/R10Protocol.swift` / `Ring/R10BLEClient.swift` per §1.2.
