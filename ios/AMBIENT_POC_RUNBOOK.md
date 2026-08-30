# Ambient iPhone PoC — build/run runbook + honesty matrix

Run the FULL Atlas crypto/identity/session/duress stack on a real iPhone, with the
phone's **ambient multimodal sensor stream** standing in for the R10 ring's
TIMING/GATING role. The ring's streamed biological signal is the **one deferred
input**; everything else is real.

> **Load-bearing invariant (do not break):** ambient sensors **TIME and GATE**;
> **QRNG VALUES**. The fused sensor window drives *when* the QRNG fires and *whether*
> the ratchet advances — it is **never** folded into a key/value. This mirrors
> "biology times; QRNG values." Proven in Python (`backend/tests/test_signal_source.py`,
> 8 tests) before the port.

---

## 1. Honesty matrix — what's real vs stood-in vs stubbed

| Component | Status | Notes |
|---|---|---|
| Face ID gate (enrol/disenrol) | **REAL** | `LocalAuthentication` biometric policy |
| Password (enrol/disenrol scope ONLY) | **REAL** | never used for ordinary operation |
| Button double-click (ordinary-decision gate) | **REAL** | explicit human confirmation |
| Secure Enclave key storage | **REAL** | `SecureEnclaveStore` on the phone's SE |
| PoLE draw · session key · epoch-wraps-LK · continuity-gated unwrap · advancing ratchet | **REAL** | `AtlasCore` (`Device`, `Presence`, `PoLE`), driven by the ambient-timed cadence |
| Duress slice (panic→decoy, zeroize-on-suspicion) | **REAL** | `PanicVault` (Swift port of the tested Python) |
| Alarm forensic window (C8) | **REAL core** | `ForensicWindow`: escape-first, sealed to recovery key, host-blind, tamper-evident. App wiring (capture source + off-device sink) is the ⌘R piece |
| Secure vault (C9) | **REAL core** | `SecureVaultStore`: presence-gated, provenance-stamped, backup choice. Files integration is the ⌘R piece. Cryptographic unreadability, not physical exclusion |
| PQC session tunnel (ML-KEM-768 + X25519) | **REAL crypto** | `HybridKEM`/`Tunnel`; the HTTP transport to the Mac is the one seam |
| Phone↔phone messages (end-to-end, blind relay) | **REAL** | `AtlasRelayClient` + `node_server`: A-B key the Mac never holds; node stores/forwards opaque ciphertext. Content E2E; **metadata visible to relay** (honest boundary) |
| **Ambient sensors as timing/gating source** | **STAND-IN** | mic/accel/gyro/magnetometer/barometer FUSED → timing+gate; `simulated=true`; **ambient-not-biological** |
| R10 ring biological continuity signal | **DEFERRED** | the one pending input; `RingSignalSource` throws — swap it in later, no pipeline change |
| App Attest device authenticity | **STUBBED** (if free provisioning) | `AtlasFlags.appAttestStubbed`; flip off with a paid team |
| Population/aggregate PoLE-arrival timing | **SIMULATED** | degenerate on one device; the wrap/unwrap/ratchet MACHINERY is real, aggregate scale needs many devices |
| Live-provenance attribution binding (Priority-1) | **DEFERRED in Swift** | ported+tested in Python; the Swift app marks attribution DEFERRED rather than faking it |

The app prints this same matrix at startup (`AtlasFlags.logHonesty()`) and shows it
on the **Ambient** tab, so nothing is silently overclaimed.

---

## 2. What this build PROVES / does NOT prove

**Proves:** the full stack runs on real Apple hardware; real Face ID + button + password
+ Secure Enclave + PQC tunnel + duress; a **live, real-time ambient signal TIMES the
draws and drives an advancing ratchet, gated correctly** (the live-gating *frame*
works); and the pipeline is **source-agnostic** (ring = a source swap, not a rebuild).

**Does NOT prove:** that the live signal is coherent *living biological* entropy (the
umbilicus / security anchor — needs the R10); population/aggregate-scale timing (needs
many devices); device authenticity if App Attest is stubbed (needs a paid account).

---

## 3. Build & run (cable + free provisioning)

### 3.0 No-terminal quickstart (recommended — zero typing)
The Mac node has a **double-click launcher**. In Finder, open the repo folder and
double-click **`Atlas-Node.command`**. The first time, if macOS blocks it,
**right-click → Open → Open** (once). It sets everything up on first run (~30s),
starts the node, and **opens the dashboard in your browser automatically**. The
dashboard shows the exact address to point the phones at. To stop it, close the
window. That's the whole Mac side — the rest is Xcode (§3.2) and the phone.

### 3.1 Prereqs
- Latest macOS + Xcode; a physical iPhone + cable.
- Free provisioning (personal Apple ID) is fine — **no paid account required** (App
  Attest stays stubbed; everything else is real).

### 3.2 Open / create the Xcode project
The repo ships the **`AtlasCore` SwiftPM package** (pure Swift, `swift test`-able) and
the **`AtlasApp` sources** (hardware-bound app target). If there is no `.xcodeproj`
yet, create the app target once and add the package:

1. Xcode → File → New → Project → **iOS App** → name `AtlasApp`, interface **SwiftUI**,
   language **Swift**. Set the bundle id to something unique (e.g. `com.yourname.atlas`).
2. Delete the template `ContentView.swift`/`App.swift`; **add the existing files** from
   `ios/AtlasApp/` (drag the folder in, "create groups"): `AtlasPoCApp.swift`, `UI/`,
   `Config/`, `Ambient/`, `Enrolment/`, `Session/`, `Enclave/`, `Ring/`, `Payment/`,
   and `Info.plist` (or copy its keys into the target's Info).
3. File → Add Package Dependencies → **Add Local…** → select `ios/AtlasCore` → add the
   `AtlasCore` library to the app target.
4. Signing & Capabilities → **Automatically manage signing** → select your **Personal
   Team**. Add the **Face ID** usage (already in `Info.plist`), and confirm the
   **Microphone** + **Motion** usage strings are present (they are, in `Info.plist`).

### 3.3 Run to the device
1. Connect the iPhone; select it as the run destination.
2. ⌘R. First run: on the phone, **Settings → General → VPN & Device Management → trust**
   your developer certificate.
3. Open the app → **Ambient** tab. Enter a password + a panic code, then tap
   **"Double-click to confirm + Enrol"** twice (the double-click gesture) and complete
   Face ID. Then exercise **Ratchet once**, **Unlock with panic code** (decoy), and
   **Panic wipe** (zeroize).

### 3.4 The 7-day free-provisioning reprovision workflow
Free-provisioned builds expire after **7 days**. To keep testing:
- Reconnect the iPhone to the Mac, open the project, and **⌘R again** — Xcode
  re-signs with a fresh 7-day certificate and reinstalls over the existing app
  (enrolment state in the Keychain/SE persists across reinstalls of the same bundle id).
- If the app was deleted or the cert fully lapsed, just re-run; you'll re-enrol.
- Personal-team limits apply (a handful of app ids active at once, ~3 devices). If you
  hit "maximum App IDs" reuse the same bundle id rather than minting new ones.

### 3.5 App Attest (optional, needs paid account)
Leave `AtlasFlags.appAttestStubbed = true` for free provisioning. With a **paid**
Apple Developer team: add the **App Attest** capability, set the flag to `false`, and
`AppAttestGate` will exercise real DeviceCheck attestation against your Mac verifier.

### 3.6 PQC tunnel to the Mac backend

**Install the backend node on the Mac (one time).** It's a small Python program,
not a `.app`. macOS ships `python3`; you only add a few pip wheels in a virtual
environment (no Xcode/compiler needed — the heavy BBS+ native lib is skipped):

```bash
cd ~/Atlas-PoC/backend                 # wherever you cloned the repo
python3 -m venv .venv                   # create an isolated environment
source .venv/bin/activate               # activate it (prompt shows (.venv))
pip install --upgrade pip
pip install -r requirements-server.txt  # cryptography + kyber-py + dilithium-py + pyspx
```

**Run the node** (leave this Terminal window open — it's the live server):
```bash
python -m atlas.net.node_server --host 0.0.0.0 --port 8787
# -> [atlas] Mac NODE (blind relay) on http://0.0.0.0:8787 — open http://<mac-lan-ip>:8787/
```
Then open **`http://<mac-lan-ip>:8787/`** in a browser — that's the **live dashboard**
you keep an eye on (auto-refreshes every 2s): registered phones/mailboxes, how many
sealed blobs have been relayed, and the opt-in public path.

> **The node is a BLIND RELAY.** Phone↔phone messages are sealed under an A-B key
> the node **never holds** — it stores & forwards **opaque ciphertext it cannot
> read**. It sees only envelope metadata (from/to mailbox, size, order). Proven by
> `test_node_server.py::test_A_to_B_message_is_end_to_end_node_is_blind`. The
> plaintext-verifying path is **opt-in and separate** — used only for content you
> deliberately publish (the "library of truths"), never for private traffic.
> Honest boundary: content is end-to-end; metadata privacy (sealed-sender/mixing)
> is a documented upgrade, not built here.
>
> `python -m atlas.net.tunnel_backend` is the older bare KEM-echo endpoint; the
> node above supersedes it for real use.

**Find the Mac's LAN IP** (so the phone can reach it — same Wi-Fi):
```bash
ipconfig getifaddr en0   # Wi-Fi; try en1 if blank. e.g. 192.168.1.42
```

**Sanity-check from the Mac itself** (new Terminal tab):
```bash
curl http://localhost:8787/status            # should print JSON {"mailboxes":[], "relayed_total":0, ...}
```

Next time you just `cd ~/Atlas-PoC/backend && source .venv/bin/activate && python -m
atlas.net.tunnel_backend` — the venv install is one-time.

Point the phone at the Mac's LAN IP: `AtlasTunnelClient(baseURL: URL(string: "http://<mac-ip>:8787")!)`,
then `handshake()` → `send(...)`. The handshake is the REAL hybrid ML-KEM+X25519
exchange; if the tunnel opens, **Swift↔Python ML-KEM interop is confirmed end-to-end**.
The combiner transcript both sides must agree on is pinned by the `xwing_combine`
parity vector (a divergence there is what would make the tunnel silently fail —
see the fix note below).

> **Cross-impl bug fixed here:** the Swift `HybridKEM.combine` was folding 4
> elements `[ssMLKEM, ssX, xEphPK, recipientXPK]` while the Python reference folds
> **5** — it includes `mlkemCT` (ciphertext transcript-binding). Their tunnel keys
> would never have matched. Swift now matches Python, and `testXWingCombine` guards
> it statically.

---

## 4. Swapping in the ring later (source-agnostic)
When the R10 arrives: implement `RingSignalSource.sample()` (or a `ClosureSignalSource`
fed by the R10 BLE stream) and change `AtlasFlags.signalSource` to `.ring`. **No
pipeline rewiring** — `timedRatchetStep`/`AtlasRuntime` consume only the `SignalSource`
interface. That swap is exactly what the Python `test_pipeline_consumes_any_source_unchanged`
and `demo_ambient_signal.py` prove.

---

## 5. Verification status
- **Python reference (verifiable now):** the SignalSource architecture + the value/timing
  invariant are **built and green** — `test_signal_source.py` (8 tests), full backend
  suite **183 passed**, `demo_ambient_signal.py` runs.
- **Swift core + app (translated, unrun on Linux):** `Session/SignalSource.swift`,
  `Session/DuressVault.swift`, and the `AtlasApp/` layer compile-check on the **Mac** —
  see `ios/MAC_TEST_RUNBOOK.md` for `swift test` (34 core tests incl. `SignalSourceTests`).
  The app target is hardware-bound and is validated by the ⌘R run above, not by
  `swift test`.
