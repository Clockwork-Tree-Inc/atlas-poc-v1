# AtlasApp — build & run (Simulator first, then one iPhone)

The `ios/AtlasApp/` sources exist but there is **no Xcode app project yet**. You
create the app target once, add the sources + the local `AtlasCore` package, and
run — first in the **iPhone 17 Pro Max Simulator** (no cable), then on **one real
iPhone** for the ambient/Secure-Enclave/camera demo.

Pre-flight status: the app↔AtlasCore interface is verified clean. The remaining
shakeout is iOS-framework calls + Swift 6 concurrency in the sensor code — expect
a round or two, same as the core had. Paste build errors and they get fixed fast.

## 1. Create the app target (one time)
1. Xcode → **File → New → Project… → iOS → App** → Next.
2. Product Name: **AtlasApp**. Interface: **SwiftUI**. Language: **Swift**.
   Bundle id: something unique, e.g. `com.clockworktree.atlas`.
   Save it **next to** the existing `ios/AtlasApp/` folder (e.g. in `ios/`).
3. **Delete** the two template files Xcode created (`AtlasAppApp.swift` /
   `ContentView.swift`) — move to Trash. (We use the ones in `ios/AtlasApp/`.)

## 2. Add the real sources
4. Drag the **contents** of `ios/AtlasApp/` (the folders: `Config`, `Ambient`,
   `Enrolment`, `Session`, `Enclave`, `Ring`, `Payment`, `UI`, plus
   `AtlasPoCApp.swift`) into the Xcode project navigator. In the dialog:
   **Copy items if needed = OFF** (reference in place), **Create groups**,
   **Add to target: AtlasApp = ON**.
5. If the template left an `Info.plist`, replace its contents with the keys from
   `ios/AtlasApp/Info.plist` (Face ID, Microphone, Motion usage strings), or add
   those keys to the target's Info settings.

## 3. Link the AtlasCore package
6. **File → Add Package Dependencies… → Add Local…** → select `ios/AtlasCore` →
   Add Package → add the **AtlasCore** library to the **AtlasApp** target.

## 4. Set the deployment target
7. Select the **AtlasApp** target → **General** → **Minimum Deployments → iOS 26.0**
   (must be ≥ 26 — AtlasCore uses CryptoKit PQC that requires it).

## 5. Run in the Simulator (no cable)
8. Destination (top bar) → **iPhone 17 Pro Max** (a Simulator).
9. **Cmd + R**.
   - Expect: the app launches, the **Ambient** tab shows the honesty banner and
     the enrol/live-session/duress UI.
   - The ambient signal will read **absent** in the Simulator (no real motion) →
     the ratchet correctly **fail-closes**. That's expected — the Simulator has
     no sensors. You're validating **build + launch + flow + networking** here,
     not the ambient timing (that's the phone).
   - Face ID in the Simulator: **Features → Face ID → Enrolled**, then use
     **Matching Face** when prompted.

## 6. Point it at the Mac node (optional, works from the Simulator)
10. Start the node: double-click `Atlas-Node.command` (dashboard opens).
11. The Simulator shares your Mac's network, so `http://localhost:8787` works
    directly for the tunnel/relay.

## 7. Then: one real iPhone (the actual demo)
12. Plug in the iPhone, select it as the destination, set signing to your
    **Personal Team** (free provisioning), **Cmd + R**, trust the cert on the
    phone (Settings → General → VPN & Device Management).
13. On the phone the ambient sensors, Secure Enclave, and camera are **real** —
    this is where the live ambient-timed ratchet actually runs. N=1 (one phone)
    demonstrates the whole on-device stack; a second phone adds phone↔phone
    messaging.

## If the build errors
Grab them (Terminal, in the app project dir): `xcodebuild -scheme AtlasApp -sdk iphonesimulator 2>&1 | pbcopy` — or Issue Navigator (⌘5) → ⌘A → ⌘C — and paste. Most likely: Swift 6 concurrency on the sensor async code; quick to fix.
