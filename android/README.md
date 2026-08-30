# Atlas — Android client (thin client scaffold)

The Android client for Atlas: a post-quantum, live-presence identity / trust / economy app.
This module mirrors the working iOS app (`ios/AtlasApp` + `ios/AtlasCore`) and talks to the
same Python node/backend (`backend/`).

## Strategy: THIN CLIENT (deliberate, locked)

This client is intentionally **thin**. It does **not** re-implement the Atlas crypto in Kotlin.
There are already two byte-parity crypto implementations (Python is the reference-of-record;
Swift `AtlasCore` matches it). A third hand-ported Kotlin crypto core would be a permanent
maintenance tax and a new place for parity bugs to hide.

So the split is:

- **The node/backend does the heavy crypto** — PoLE, epoch-wrap, the continuity ratchet, and
  the real hybrid post-quantum KEM (ML-KEM-768 + X25519). The phone reaches it over the tunnel.
- **The Android app does three things**: (a) hardware key-ops via Android Keystore / StrongBox
  and BiometricPrompt, (b) the UI, (c) the tunnel to the node.

### Future direction: one shared core (not a Kotlin port)

The convergence target is **a single shared Rust core exposed via UniFFI** to Swift + Kotlin +
Python. That replaces "three parallel implementations" with "one implementation, three bindings"
— and only then does meaningful crypto live in-process on Android. Until that core exists, this
client stays thin and delegates to the node. See `net/NodeClient.kt`.

## What is scaffolded

Kotlin + Jetpack Compose + Material3, single-activity, `minSdk 26` / `targetSdk 35`.

**UI surfaces** (mirror the iOS app), under `app/src/main/java/com/clockworktree/atlas/ui/`:

| Screen | File | Mirrors (iOS) |
| --- | --- | --- |
| Enrolment wizard | `EnrolmentScreen.kt` | `EnrolView.swift` |
| Home (personas) | `HomeScreen.kt` | `HomeView` / `HomeTabView` |
| Spaces (recursive tree) | `SpacesScreen.kt` | `SpacesTabView` / `SpaceNavigatorView` |
| Chat + AI librarian | `ChatScreen.kt` | `MessagingView` |
| Capture (photo/video/audio) | `CaptureScreen.kt` | `CaptureTabView` |
| Document editor + Office | `DocumentEditorScreen.kt` | `DocumentEditorView` / `OfficeTabView` |

Honesty invariants carried over from iOS and enforced in `session/AtlasSession.kt`:

- Personas: exactly **ONE Real-ID slot** + N pseudonyms; the base persona is **anonymous**.
- **NOTHING shows "verified."** Real-ID verification is not built, so `isVerified` is hard-wired
  `false` and the Market stays ID-gate-closed.
- The document editor has a Title field, a **read-only Author** taken from the signing identity,
  and **one** writing surface — no add-block UI.
- The chat "librarian" **surfaces + cites** from your library and never invents answers
  (retrieval is a stub; see `AtlasSession.aiReplyIfPresent`).

**Hardware seams** (stubs with explicit `TODO`s), under `.../hardware/`:

| Seam | File | iOS equivalent |
| --- | --- | --- |
| Keystore / StrongBox | `KeystoreSeam.kt` | Secure Enclave (`SecureEnclaveStore`) |
| BiometricPrompt | `BiometricSeam.kt` | Face ID / Touch ID |
| Play Integrity | `PlayIntegritySeam.kt` | App Attest (`AppAttestGate`) |
| BLE GATT | `BleSeam.kt` | CoreBluetooth (`RingProbe` / `R10BLEClient`) |
| SensorManager | `SensorSeam.kt` | CoreMotion (`AmbientSensorSource`) |
| IsoDep NFC | `NfcSeam.kt` | passport / eID NFC (`Card2NFCSession`) |
| Credential Manager | `CredentialManagerSeam.kt` | passkeys / FIDO2 (`RPClient`) |
| CameraX | `CameraSeam.kt` | camera (`CaptureController`) |

**Networking**: `net/NodeClient.kt` — thin HTTP client to the node (`ping` works; the PQC
handshake + sealed `send` are TODOs that will call the shared core, not a Kotlin KEM).

## Build status — NOT yet built (honest)

This scaffold has **not been compiled**. The machine it was authored on has **no Android
toolchain installed** (no `gradle`, no `ANDROID_HOME`/`ANDROID_SDK_ROOT`, no `sdkmanager`, and
no Java runtime). So:

- The code is written to compile against the pinned versions in `gradle/libs.versions.toml`,
  but **a successful build has not been demonstrated.**
- `gradle/wrapper/gradle-wrapper.jar` (a binary) is **not committed**. The wrapper scripts
  (`gradlew`, `gradlew.bat`) and `gradle-wrapper.properties` are present; the jar is regenerated
  on first Android Studio sync or by `gradle wrapper` (see below).

Treat any "it builds" claim as unverified until you run one of the paths below.

## How to build

### Option A — Android Studio (easiest)

1. Install Android Studio (Ladybug / 2024.2+), which bundles a JDK 17 and the Android SDK.
2. `File > Open` -> select this `android/` folder.
3. Let it sync. Android Studio will **generate the Gradle wrapper jar** and download the SDK
   platform (API 35) + build-tools automatically.
4. Run on an emulator (API 26+) or a device with USB debugging: press **Run**.

### Option B — command line

Prerequisites (none of these are currently installed on the author's machine):

```sh
# 1. A JDK 17 (Temurin/Homebrew both fine on macOS)
brew install temurin@17            # or: brew install openjdk@17
export JAVA_HOME="$(/usr/libexec/java_home -v 17)"

# 2. Android command-line tools + SDK
brew install --cask android-commandlinetools
export ANDROID_HOME="$HOME/Library/Android/sdk"
export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"
sdkmanager --install "platforms;android-35" "build-tools;35.0.0" "platform-tools"
yes | sdkmanager --licenses

# 3. A standalone Gradle, only to generate the wrapper jar the first time
brew install gradle
cd android
gradle wrapper --gradle-version 8.11.1
```

Then, from `android/`:

```sh
# Point the build at your SDK (or set ANDROID_HOME as above)
echo "sdk.dir=$ANDROID_HOME" > local.properties

./gradlew assembleDebug        # build the debug APK
./gradlew installDebug         # install to a connected device/emulator
```

The APK lands at `app/build/outputs/apk/debug/app-debug.apk`.

## Connecting to the node

`AtlasSession.nodeUrl` defaults to `http://10.0.2.2:8000` — `10.0.2.2` is the host-loopback
alias from the Android emulator, so a node running on your Mac (`backend/`) is reachable there.
For a physical device, set it to the Mac's LAN IP. The transport is plain HTTP for now; the PQC
tunnel is a TODO (see `NodeClient.kt`).

## Do not touch

`ios/` and `backend/` are the existing, working clients — this module is additive and never
modifies them.
