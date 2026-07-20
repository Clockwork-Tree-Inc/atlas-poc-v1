# Handoff — the two-phone live-LK run (options 1 + 2)

This is the package for **the Mac-side build**. It carries everything built in
the cloud toward the milestone: **two iPhones co-deriving a live LK through the Mac
node and passing forward-secret messages on real hardware.** The cloud side is
Python (reference-of-record, verified) + Swift source (authored, **not** compiled —
Linux can't build Swift). Your job is to compile, run the gate, and run the flow.

## Discipline (unchanged)

- **Python is reference-of-record.** The whole engine (incl. `realid`/live-binding
  the Swift doesn't have yet) is proven in Python. The **two-phone Swift run mirrors
  the ported subset** — do not let "engine proven" become "proven on the phones"
  until the device run happens. Say it exactly that way.
- **The gate is `swift build && swift test` on the Mac.** Do not merge unverified
  Swift to main. This handoff branch is `integrate-poc`.

---

## Step A — run the AtlasCore gate (do this first)

New pure-Swift ports of the Python reference, each with an XCTest mirror:

| Swift file | mirrors Python | test |
|---|---|---|
| `AtlasCore/Sources/AtlasCore/Session/LiveLK.swift` | `session/live_lk.py` | `LiveLKTests.swift` |
| `AtlasCore/Sources/AtlasCore/Session/FSConversation.swift` | `session/fs_conversation.py` | (exercised via Conversation) |
| `AtlasCore/Sources/AtlasCore/Session/Conversation.swift` | `session/conversation.py` | `ConversationTests.swift` |
| `AtlasCore/Sources/AtlasCore/Session/MediaVaultStore.swift` | `session/media_vault.py` | `MediaVaultTests.swift` |
| `AtlasCore/Sources/AtlasCore/Session/SignalSource.swift` (change-detect) | `session/signal_source.py` | `ChangeDetectionTests.swift` |
| `AtlasCore/Sources/AtlasCore/Liveness/Entropy.swift` + `GBSS.swift` | `liveness/entropy.py` + `gbss.py` | `EntropyTests.swift` |

```bash
cd ios/AtlasCore
swift build
swift test
```

**Expected:** all AtlasCore tests pass, including the new LiveLK / Conversation /
MediaVault suites. If any fail, they are almost certainly a Swift↔Python core
mismatch (HKDF `info`/order, `H` chunking, byte order) — fix the Swift to match the
Python reference, never the reverse. The crypto cores were written to be
byte-identical (`atlas/live-lk/co-derived`, `atlas/fs-conv/chain`,
`atlas/conv/aad`, `atlas/conv/sig-core`).

> Parity gap that is expected, not a bug: `MediaVaultStore` accountability is the
> current Swift provenance scope (integrity + handle + signature + liveness +
> anchor). The Python `MediaVault` also folds the Priority-1 live-LK/session
> binding, which the Swift `Provenance` core hasn't ported yet. It is documented in
> the file, not faked.

---

## Step B — run the Mac node (it already serves)

The node is a real HTTP server (verified in the cloud: registered two phones,
relayed an opaque blob A→B, B fetched it, node stayed blind):

```bash
cd backend
python -m atlas.net.node_server --host 0.0.0.0 --port 8787
```

Open `http://localhost:8787/` — the dashboard prints **`Point the phones here:
http://<mac-lan-ip>:8787`**. That LAN IP is what the phones use.

---

## Step C — phones reach the Mac (the networking answer)

**Yes, the Mac runs as a reachable server the phones connect to over your local
network** — that's what Step B is. `--host 0.0.0.0` binds all interfaces, so the
phones hit `http://<mac-lan-ip>:8787`. The practical gaps between "node serves" and
"two phones connect and run the flow" — name these now so the run doesn't stall:

1. **Same Wi-Fi.** Mac and both phones on one LAN. Get the Mac's IP:
   `ipconfig getifaddr en0` (Wi-Fi) — this is the `<mac-lan-ip>`.
2. **iOS Local Network permission.** iOS gates LAN access. Add to the app's
   `Info.plist`:
   ```xml
   <key>NSLocalNetworkUsageDescription</key>
   <string>Atlas connects to your Mac node on the local network for the two-phone run.</string>
   ```
   The first connection triggers a permission prompt — tap Allow on each phone.
3. **Cleartext HTTP (ATS).** The node is plain `http://` on the LAN. Add an ATS
   exception so iOS allows it (local dev only):
   ```xml
   <key>NSAppTransportSecurity</key>
   <dict>
     <key>NSAllowsLocalNetworking</key><true/>
   </dict>
   ```
   (`NSAllowsLocalNetworking` covers `.local` and raw LAN IPs without disabling ATS
   globally.) The production path is TLS on the node; not needed for the run.
4. **Firewall.** If the macOS firewall is on, allow incoming connections for
   `python` (System Settings → Network → Firewall).

That's the whole "phones-reach-the-Mac" list. Nothing else is hidden.

---

## Step D — the two-phone live-LK run

New app pieces (added to the synchronized Xcode folder, so they build in
automatically — no project edits needed):

- `AtlasApp/Messaging/FSRelayClient.swift` — register → KEM channel → **exchange
  live-LK contributions (blind) → co-derive identical LK** → forward-secret
  `Conversation` over the relay (whole envelope sealed under the A-B key → node sees
  fully opaque bytes).
- `AtlasApp/UI/MessagingView.swift` — the run UI, added as a **Messaging** tab in
  `ContentView`.

Run it:

1. Build the app to **both** iPhones (Xcode).
2. On both: open the **Messaging** tab, set the Mac URL to `http://<mac-lan-ip>:8787`.
3. Phone 1: mailbox `phoneA`, peer `phoneB`. Phone 2: mailbox `phoneB`, peer
   `phoneA`. Tap **Register** on both (watch the mailboxes appear on the Mac
   dashboard).
4. On **one** phone tap **Begin live LK**. Both phones show **`live LK ✓ <prefix>…`**
   with the **same** prefix — that's the co-derived LK, live on the hardware.
5. Type messages both ways. They pass forward-secret; the Mac dashboard shows only
   opaque relayed blobs (blind).

> First run is **DENIABLE** mode (symmetric auth) so no peer authorship-public
> exchange is needed. ACCOUNTABLE mode (non-repudiable signatures) is a documented
> next step: exchange the two `authorship.publicKey`s (e.g. print/scan or relay
> them once) and pass `mode: .accountable` + `peerPublic:` into `FSRelayClient`.

---

## Step E — audio → vault (the media slice, ready to wire)

`AtlasApp/Capture/AudioCaptureController.swift` records with `AVAudioRecorder` and
calls `onAudio(bytes, name)`. Wire it to seal into the vault via a
`MediaVaultStore` built from the enrolled `SecureVaultStore` + authorship child.
The ~10-line seam (in whatever view/model owns the live session context):

```swift
let media = MediaVaultStore(vault: secureVaultStore, authorship: authorshipChild)
let audio = AudioCaptureController()
audio.onAudio = { data, name in
    // live gating values from the current session (pole/attestation/beacon/biometric)
    try? media.capture(kind: .audio, name: name, content: data,
                       liveBiometric: enrolledBiometric, pole: currentPoLE,
                       beacon: currentBeaconRound, attestation: freshAttestation)
}
// audio.requestPermissionAndStart() / audio.stop()
```

Add `NSMicrophoneUsageDescription` to `Info.plist`. Camera→video and the Files-app
File Provider are the next media slices (documented, not yet built).

---

## Sequence after this run (per the agreed plan)

1. **This run** — live LK + FS messaging on the two phones (options 1 + 2). ← here
2. **Then `realid/` to Swift** (option 3) — the biggest identity gap; adds full
   engine coverage on-device and unlocks the live-provenance binding in the Swift
   `MediaVaultStore`.
3. Camera→video capture, File Provider (vault as a Files folder), accountable-mode
   identity exchange.
