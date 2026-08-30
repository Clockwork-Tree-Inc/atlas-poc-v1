import Foundation
import AtlasCore
#if canImport(UIKit)
import UIKit
#endif

/// The ONE shared app session: a single enrolment ritual establishes the identity,
/// live presence, and the crypto stores — then EVERY feature (vault, messaging,
/// camera, auth, recovery) uses THIS session's enrolled authorship + live presence,
/// instead of each screen minting a throwaway identity. Injected app-wide as an
/// `@EnvironmentObject`; features are locked until `enrolled == true`.
///
/// Presence is source-agnostic: the ambient signal drives it today; the R10 ring
/// swaps in with no change here (AtlasFlags.signalSource). One live-presence gate
/// (`currentPoLE`) backs the ratchet, the vault release, capture attestation, and
/// the auth assertion — the same "is a living human here right now" for all of them.
@MainActor
final class AtlasSession: ObservableObject {

    @Published private(set) var enrolled = false
    @Published var log: [String] = []
    @Published private(set) var enrolProgress: [String] = []   // the one-motion enrol checklist

    /// The liveness tier this identity enrolled under — ambient (phone sensors, the
    /// default floor) or ring (biological pulse, the optional step-up). Recorded so a
    /// proof never claims stronger liveness coverage than it actually had.
    enum LivenessTier: String { case ambient, ring
        var label: String { self == .ring ? "ambient mode + live ring pulse" : "ambient mode" }
    }
    @Published private(set) var enrolTier: LivenessTier = .ambient

    // Established at enrolment, then read by every feature:
    private(set) var identity: IdentityTree?
    var authorship: Child? { identity?.child(.authorship) }

    // PERSONAS — each is its OWN unlinkable stack ("from vault onward") derived off the blind
    // System-ID (`Profile`). `currentPersona` is the identity you're acting as; switching re-opens
    // THAT persona's own vault (keyed by its `feature("vault")` slice). The System-ID link never
    // surfaces, and personas are mutually unlinkable to anyone holding only handles.
    @Published private(set) var currentPersona: Profile?
    @Published private(set) var personas: [Profile] = []
    /// The current persona's hosting LAND (its own space for forum/market/hosted content),
    /// swapped on every persona switch — parallel to the vault. `nil` until a persona is active.
    @Published private(set) var land: Spaces.PersonaLand?
    /// Items hosted in the current persona's land (commitments; refreshed on host/switch).
    @Published private(set) var hostedItems: [Spaces.SpaceItem] = []
    private var landClock: UInt64 = 0
    /// The human-readable name claimed for the current persona (its discoverable "domain"), if any.
    @Published private(set) var claimedName: String?
    private let nameRegistry = Names.NameRegistry()

    /// Open the vault + media store for a persona, keyed by its per-persona vault slice
    /// (`feature("vault")`) so each persona's contents are isolated. Falls back to the identity
    /// authorship child if no persona is available (should not happen post-enrolment).
    private func openVault(for persona: Profile?, fallback: Child) {
        let vaultAuthor = (persona.flatMap { try? $0.feature("vault") }) ?? fallback
        // Reopen this persona's PERSISTED vault (at-rest blob: sealed key + ciphertexts) if one
        // exists — so content survives relaunches; otherwise a fresh vault (#37).
        let v: SecureVaultStore
        if let blob = UserDefaults.standard.data(forKey: vaultBlobKey(for: persona)),
           let restored = SecureVaultStore(restoringFrom: blob, enclave: enclave,
                                           biometric: biometric, author: vaultAuthor, backup: .phoneOnly) {
            v = restored
        } else {
            v = SecureVaultStore(enclave: enclave, biometric: biometric, author: vaultAuthor, backup: .phoneOnly)
        }
        self.vault = v
        self.media = MediaVaultStore(vault: v, authorship: vaultAuthor)
    }

    /// Re-open the current persona's hosting LAND (forum/market/hosted content live here), keyed
    /// by the persona so each persona's spaces are isolated — swapped on every switch, like the vault.
    private func openLand(for persona: Profile?) {
        land = persona.flatMap { try? Spaces.createLand(for: $0) }
        hostedItems = land.map { $0.hosted(now: landClock) } ?? []
    }

    /// Host arbitrary bytes into the current persona's land (owner-gated, committed), then refresh.
    /// The commitment lives in the land; sealing the bytes into the vault is the app-layer follow-on.
    func hostToLand(_ content: Data) {
        guard let land else { return }
        landClock += 1
        _ = try? land.host(content, now: landClock)
        hostedItems = land.hosted(now: landClock)
    }

    /// Reviews: the current persona likes/dislikes a hosted item (one last-wins vote per persona).
    @Published private(set) var votes: [Social.Vote] = []
    func vote(on target: Data, up: Bool) {
        guard let p = currentPersona,
              let v = try? Social.castVote(by: p, target: target, up: up, epoch: landClock) else { return }
        votes.removeAll { $0.nullifier == v.nullifier }   // replace this persona's prior vote on this target
        votes.append(v)
    }
    func score(for target: Data) -> Social.Score { Social.tally(target: target, votes: votes) }

    /// Claim a human-readable name for the current persona (its discoverable address). Unique and
    /// signed by the persona's key — only the holder can claim a name for their handle. Returns
    /// false if empty, no active persona, or the name is already taken.
    @discardableResult
    func claimName(_ name: String) -> Bool {
        let n = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !n.isEmpty, let p = currentPersona else { return false }
        do {
            try nameRegistry.register(try Names.claimName(p.identity, name: n))
            claimedName = n
            return true
        } catch { return false }
    }

    /// Create a new persona (its own unlinkable stack) off the enrolment System-ID and switch to it.
    func createPersona(_ username: String, tier: PseudonymTier = .anonymous) {
        guard let identity, let p = try? identity.profile(username, tier: tier) else { return }
        if !personas.contains(where: { $0.handle == p.handle }) { personas.append(p); persistSession() }
        switchPersona(p)
    }

    /// Switch the active persona — re-opens that persona's OWN vault/media (its own life).
    func switchPersona(_ persona: Profile) {
        // Persist the OUTGOING persona's sealed space graph into ITS vault BEFORE the swap
        // (persistGraph captures the outgoing vault + snapshot synchronously, so it cannot bleed
        // into the incoming persona's vault).
        persistGraph()
        // ISOLATION: persist ALL of the OUTGOING persona's per-persona state before swapping —
        // nothing persona-scoped may bleed across personas. (Full audited set: files, votes,
        // claimed name, default-capture folder, message history. vault/media re-open below;
        // land/hostedItems reload via openLand; spaceRoots are already keyed per handle.)
        if let out = currentPersona?.handle {
            vaultFilesByPersona[out] = vaultFiles
            votesByPersona[out] = votes
            claimedNameByPersona[out] = claimedName
            defaultCaptureFolderByPersona[out] = defaultCaptureFolderID
            defaultCaptureByTypeByPersona[out] = defaultCaptureByType
            historyByPersona[out] = messages
        }
        currentPersona = persona
        if let fallback = authorship { openVault(for: persona, fallback: fallback) }
        openLand(for: persona)
        // Take the current relay offline (it was registered under the previous persona's
        // mailbox) and clear live group state; reconnect brings it online as this persona.
        group?.stop(); group = nil; nodeConnected = false
        peerLive = false; roster = []; safetyNumber = ""
        // Load the INCOMING persona's per-persona state (each persona = its own whole world).
        messages = historyByPersona[persona.handle] ?? []
        vaultFiles = vaultFilesByPersona[persona.handle] ?? []
        votes = votesByPersona[persona.handle] ?? []
        claimedName = claimedNameByPersona[persona.handle]
        defaultCaptureFolderID = defaultCaptureFolderByPersona[persona.handle]
        defaultCaptureByType = defaultCaptureByTypeByPersona[persona.handle] ?? [:]
        let code = persona.handle.prefix(4).map { String(format: "%02x", $0) }.joined()
        add("persona → \(code) · isolated vault + messaging + history")
        loadGraph(for: persona)   // restore this persona's sealed space graph (async, #18)
    }

    // The ID clock: pseudonyms are DERIVED from the anonymous System-ID, one per
    // context, mutually unlinkable, and RATCHETED per pseudonym epoch. The System-ID
    // itself never appears anywhere.
    @Published private(set) var pseudonymEpoch = 0

    /// A derived pseudonym for `context` — linked to the System-ID (resolvable only
    /// under authorized cause), unlinkable to other contexts, and rotated by the ID
    /// clock. Different context OR different epoch -> a different, uncorrelatable handle.
    func contextPseudonym(_ context: String, tier: PseudonymTier = .anonymous) -> Child? {
        try? identity?.pseudonym("\(context)#e\(pseudonymEpoch)", tier: tier)
    }

    /// Ratchet the System-ID forward (the ID clock): every context pseudonym
    /// re-derives to a fresh unlinkable handle. Forward-unlinkability — nothing ties
    /// yesterday's handles to today's, and no static identifier ever exists.
    func rotateSystemID() {
        pseudonymEpoch += 1
        add("System-ID ratcheted → pseudonym epoch \(pseudonymEpoch); all context handles rotated (unlinkable).")
    }
    private(set) var device: Device?
    private(set) var enrolmentSecret: Data?
    private(set) var epoch: (wrappedEpochKey: Data, wrappedLK: Data)?

    // The LIVING session after enrolment: the continuity ratchet advances on its own
    // on the live ambient/ring timing (no buttons). The LK / continuity value is
    // NEVER published — only "running / ticks / present" is surfaced. Fully private.
    @Published private(set) var running = false
    @Published private(set) var ratchetTicks = 0
    @Published private(set) var presenceLive = false
    // Live-presence lifecycle (PRESENT/SUSPENDED/LOCKED). Driven by the ring pulse ONLY
    // while a ring is connected — a ring-off beyond the grace window is a HARD LOCKDOWN
    // (wipe the live layer, keep the sealed identity). Guarded so a ring-less or transiently
    // flaky session is never bricked. On the R10 resume is pulse-based (it can't hold codes).
    @Published private(set) var presenceLocked = false
    private var presence: PresenceSession?
    private static let presenceGraceS = 60.0

    // #42 unlock tiers + presence state machine. `effectiveTier` is the live answer to "what may
    // this session do right now": the ceiling reached at unlock, LOWERED to .standard whenever live
    // presence goes stale (no PoLE tick within the freshness window). Duress caps it at .duress.
    // Clock = wall-clock seconds (a monotonic round the device session can later swap for the beacon).
    private var presenceUnlock = PresenceUnlock.State()
    private let presenceUnlockPolicy = PresenceUnlock.Policy(freshnessWindowRounds: 8)   // ~8s freshness
    @Published private(set) var effectiveTier: PresenceUnlock.UnlockTier = .locked
    private func unlockRound() -> UInt64 { UInt64(max(0, Date().timeIntervalSince1970)) }
    private func refreshEffectiveTier() {
        effectiveTier = PresenceUnlock.effectiveTier(presenceUnlock, presenceUnlockPolicy, nowRound: unlockRound())
    }
    /// Gate a capability on the CURRENT tier (unlock ceiling lowered by presence freshness).
    func meetsTier(_ tier: PresenceUnlock.UnlockTier) -> Bool {
        PresenceUnlock.allows(presenceUnlock, presenceUnlockPolicy, nowRound: unlockRound(), required: tier)
    }

    // Attestation mode + measurement (battery test): sign a full PQC LivenessAttestation
    // EVERY tick (attestEveryTick = true) vs only on demand (false). The counters let
    // us measure the real cost on-device.
    @Published var attestEveryTick = false
    @Published private(set) var sigCount = 0
    @Published private(set) var avgSignMs = 0.0

    // Opt-in PROOF RECORDING: for something worth it (a video), capture the per-tick
    // live id-attestations across the recording window into an exportable proof.
    // Bounded to the window (you only pay the storage when it matters).
    @Published private(set) var proofRecording = false
    @Published private(set) var proofTicks = 0
    // Storage policy — YOU decide: a short ROLLING log (keep last `retentionHours`,
    // auto-pruned) for everyday material, OR an explicit per-recording bundle for
    // something worth more, OR neither (cheapest). "Keep a day's log" = rolling, 24h.
    @Published var proofLogging = false           // rolling log on/off
    @Published var retentionHours = 24.0          // rolling window ("a day")
    private var proofLog: [[String: Any]] = []    // entries: ["at": epochSecs, "sig": b64]
    private var proofStartedAt = Date()
    private var proofLabel = ""
    private var epochLK: Data?          // raw LK (co-derived) — private, permeates everything
    private var epochKeyValue: Data?    // the SECRET epoch key (global cloud value; presence-gated) — wraps the LK
    private var wrappedEpochKey: Data?  // epoch key held to the enrolment secret (presence path)
    private var epochBeacon: BeaconRound?   // the public epoch clock (drand stand-in)
    private var sessionKey: Data?           // current device session key — chained, id-bound, private
    private var coreSessionEstablished = false   // biometric release happens ONCE (not per tick)
    private var ratchetTask: Task<Void, Never>?

    // GROUP live session: any number of NAMED users join (2 is the minimum to go
    // live). Members are discovered from the node roster; everyone co-derives ONE
    // shared group LK. A lone user waits at `peerLive == false`.
    // The relay node — set YOUR node's HTTPS URL in Settings ▸ Node (e.g. https://your-node.example.com,
    // a box running `deploy/install-node.sh` behind Caddy/TLS). No operator server is hardcoded: an
    // open build must not ship someone else's live relay as the default. Empty = not configured.
    @Published var nodeURL = UserDefaults.standard.string(forKey: "atlas.node.url") ?? "" {
        didSet {
            UserDefaults.standard.set(nodeURL, forKey: "atlas.node.url")
            // Auto-start the relay as soon as a URL is set after enrol — otherwise enrolling with no
            // URL yet leaves the relay unstarted and only the settings button would revive it.
            if enrolled, !nodeURL.isEmpty, nodeURL != oldValue { reconnectGroup() }
        }
    }
    /// The public Atlas network server (Zurich). Every participant is a NODE — this is the
    /// always-on one. Reachability is probed live for the Home health row.
    /// Health-probe target = the configured node (no operator server hardcoded in an open build).
    static var publicServerURL: String {
        UserDefaults.standard.string(forKey: "atlas.node.url") ?? ""
    }
    @Published private(set) var serverReachable = false
    @Published private(set) var serverBeaconRound: Int = 0

    // MARK: - push (content-free wake)

    /// Notification posture. Default OFF = fetch-on-open: the app NEVER registers with Apple, so
    /// Apple gets no signal you're an Atlas user; you see messages when you open the app. Turning
    /// this on opts into APNs silent wakes (Apple learns device+timing, never content/sender).
    var pushEnabled: Bool {
        get { UserDefaults.standard.bool(forKey: "atlas.notif.push") }
        set {
            UserDefaults.standard.set(newValue, forKey: "atlas.notif.push")
            if newValue { PushManager.shared.start() }   // opt-in now registers
        }
    }

    private var pushTokenHex: String?

    /// Bind this device's APNs token to the current persona's mailbox on the node, so the node can
    /// send a silent wake when a sealed blob arrives. Re-sent whenever the persona/mailbox changes.
    func registerPushToken(_ hex: String) {
        pushTokenHex = hex
        sendPushRegistration()
    }

    private func sendPushRegistration() {
        guard let hex = pushTokenHex, let p = currentPersona,
              let url = URL(string: nodeURL + "/push/register") else { return }
        let mailbox = p.handle.map { String(format: "%02x", $0) }.joined()
        var req = URLRequest(url: url); req.httpMethod = "POST"; req.timeoutInterval = 8
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try? JSONSerialization.data(withJSONObject: ["mailbox": mailbox, "token": hex])
        Task { _ = try? await URLSession.shared.data(for: req) }
    }

    /// A silent push woke us: pull anything waiting in the relay so the local notification is real.
    @MainActor
    func onPushWake() async {
        if group != nil { reconnectGroup() }        // refresh the roster/inbox if we have a session
        add("push wake — checked mailbox")
    }

    func checkServer() {
        let base = Self.publicServerURL
        guard !base.isEmpty, let url = URL(string: base + "/beacon") else {
            serverReachable = false; return                 // no node configured yet
        }
        Task { [weak self] in
            // Retry a few times: a single probe can miss during a node restart or a cold radio.
            for attempt in 0..<3 {
                var req = URLRequest(url: url)
                req.timeoutInterval = 8
                req.cachePolicy = .reloadIgnoringLocalCacheData
                if let (data, resp) = try? await URLSession.shared.data(for: req),
                   (resp as? HTTPURLResponse)?.statusCode == 200 {
                    var round = 0
                    if let j = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                        round = (j["round"] as? Int) ?? (j["round"] as? NSNumber)?.intValue ?? 0
                    }
                    await MainActor.run { self?.serverReachable = true; self?.serverBeaconRound = round }
                    return                                   // reachable on any 200 (round is a bonus)
                }
                try? await Task.sleep(nanoseconds: 1_500_000_000)
                _ = attempt
            }
            await MainActor.run { self?.serverReachable = false }
        }
    }

    // The node's SearXNG (live wider-web search for the AI) — empty = off.
    @Published var nodeSearchURL = UserDefaults.standard.string(forKey: "atlas.node.searx") ?? "" {
        didSet {
            UserDefaults.standard.set(nodeSearchURL, forKey: "atlas.node.searx")
            // Default web search through the node's /search proxy (over HTTPS) when no explicit searx
        // URL is set — so the phone never needs to reach an HTTP searx port directly (ATS-blocked).
        WebLibrary.nodeSearchBase = nodeSearchURL.isEmpty ? (nodeURL.isEmpty ? nil : nodeURL) : nodeSearchURL
        }
    }
    @Published var username = ""                            // this user's name
    @Published private(set) var roster: [String] = []       // OTHER members currently online
    @Published private(set) var peerLive = false            // group LK co-derived (>= 2 online)
    @Published private(set) var messages: [String] = []
    /// Incoming messages received over the live relay from other humans — the chat UI mirrors
    /// these into the open conversation so two phones actually SEE each other's messages.
    @Published var relayMessages: [ChatMessage] = []
    @Published private(set) var safetyNumber = ""           // OOB fingerprint of verified member identities (MITM check)
    private var group: GroupRelay?
    // Per-persona message history — keyed by persona handle, so each persona keeps its OWN
    // conversation history and switching swaps it. `messages` mirrors the ACTIVE persona's.
    private var historyByPersona: [Data: [String]] = [:]

    /// Append to the active persona's history (and the live `messages` view).
    private func appendMessage(_ line: String) {
        messages.append(line)
        if let h = currentPersona?.handle { historyByPersona[h] = messages }
    }

    private(set) var vault: SecureVaultStore?
    private(set) var media: MediaVaultStore?
    let ledger = LedgerStub()

    // MARK: - the app-side space spine ("everything is a space")

    /// Per-profile in-memory space-graph. Each profile IS its own whole environment: switching
    /// profiles switches root spaces. Keyed by the profile's opaque handle (never a System-ID).
    private var spaceRoots: [Data: AppSpace] = [:]
    /// Profiles that have completed identity verification (ePassport is a later slice). Gates the
    /// Market/economy: an un-verified profile sees a "verify" wall instead of listings — no black
    /// market. `@Published` so the gate flips live the moment a profile verifies.
    @Published private(set) var verifiedProfiles: Set<Data> = []

    /// This profile's root space — created (and cached) on first access, seeded with a starter
    /// set of child spaces so the Reddit-style cascade is demonstrable out of the box. The root is
    /// the profile's `vault` space (on-device). NOTE: the Market is NOT seeded here — it is a
    /// single server-hosted space reached from the top-level Market tab, not a child of every
    /// personal vault (that was a duplicate).
    func spaceRoot(for profile: Profile) -> AppSpace {
        if let root = spaceRoots[profile.handle] { return root }
        let title = profile.username.isEmpty ? "Vault" : "\(profile.username)’s Vault"
        // The vault IS the device-hardware warehouse space. The ONLY thing seeded is a
        // "Media" folder — the default destination for the Capture tab (you asked for a
        // default media folder inside the vault). Everything else you create yourself; no
        // pre-named folders.
        let media = AppSpace(name: "Media", kind: .folder, persistence: .device)
        let root = AppSpace(name: title, kind: .vault, persistence: .device, children: [media])
        spaceRoots[profile.handle] = root
        if defaultCaptureFolderID == nil { defaultCaptureFolderID = media.id }
        return root
    }

    /// The active profile's root space (its vault), or nil if no profile is selected.
    var currentRoot: AppSpace? { currentPersona.map { spaceRoot(for: $0) } }

    /// The folder the Capture tab saves into — user-selectable (defaults to "Media").
    @Published var defaultCaptureFolderID: UUID?
    /// Per-TYPE default capture folders (category -> folder id): photos, video, audio, documents each
    /// route to their own chosen folder, falling back to the single default above. Per-persona.
    @Published var defaultCaptureByType: [String: UUID] = [:]
    func defaultCaptureFolder() -> AppSpace? {
        guard let root = currentRoot else { return nil }
        if let id = defaultCaptureFolderID, let f = root.find(id) { return f }
        return root.children.first { $0.name == "Media" } ?? root
    }
    func setDefaultCaptureFolder(_ id: UUID) { defaultCaptureFolderID = id; persistGraph() }

    /// Category a capture `kind` routes under: image->photo, video, audio, everything else->document.
    static func captureCategory(for kind: String) -> String {
        switch kind {
        case "image": return "photo"
        case "video": return "video"
        case "audio": return "audio"
        default:      return "document"   // doc / pdf / text / file
        }
    }

    /// The folder a capture of this `kind` should land in: its per-type default if set, else the
    /// single general default (-> "Media" -> root).
    func defaultCaptureFolder(for kind: String) -> AppSpace? {
        guard let root = currentRoot else { return nil }
        if let id = defaultCaptureByType[Self.captureCategory(for: kind)], let f = root.find(id) { return f }
        return defaultCaptureFolder()
    }

    /// Set this folder as the default for a capture CATEGORY ("photo"/"video"/"audio"/"document").
    func setDefaultCaptureFolder(_ id: UUID, for category: String) {
        defaultCaptureByType[category] = id; persistGraph()
    }

    // MARK: - Sealed per-persona space-graph persistence (#18)

    /// Reserved vault key for the sealed space-graph snapshot. Written via `vault.put` directly
    /// (NOT `vaultAddFile`) so it never appears in the user's file list.
    static let graphKey = "__atlas.spacegraph.v1__"

    /// Seal the CURRENT persona's space-graph snapshot into ITS vault. The vault reference and the
    /// snapshot are captured SYNCHRONOUSLY, so a concurrent persona switch cannot bleed one
    /// persona's graph into another's vault. Fire-and-forget; if there is no live presence to seal
    /// under it is skipped and re-persisted on the next mutation/switch.
    private var persistTask: Task<Void, Never>?

    /// Debounced persist: coalesce rapid changes (e.g. several quick messages) into ONE
    /// biometric-gated vault write, so we don't re-prompt Face ID per message. `flushGraph()`
    /// forces an immediate write (call it when backgrounding so nothing is lost).
    func persistGraph() {
        persistTask?.cancel()
        persistTask = Task { @MainActor in
            try? await Task.sleep(nanoseconds: 1_800_000_000)   // ~1.8s quiet window
            guard !Task.isCancelled else { return }
            self.persistGraphNow()
        }
    }

    func flushGraph() { persistTask?.cancel(); persistTask = nil; persistGraphNow() }

    private func persistGraphNow() {
        guard let vault = self.vault, let handle = currentPersona?.handle,
              let root = spaceRoots[handle] else { return }
        let snap = GraphSnapshot(space: root.snapshot(), defaultCaptureFolderID: defaultCaptureFolderID,
                                 defaultCaptureByType: defaultCaptureByType)
        guard let data = try? JSONEncoder().encode(snap) else { return }
        let bio = biometric
        Task { @MainActor in
            let pole = await currentPoLE()
            guard pole.operate else { return }
            do {
                try vault.put(Self.graphKey, data, liveBiometric: bio, pole: pole, beacon: beacon())
                self.saveVaultAtRest()   // spill the (ciphertext-only) vault to disk — survives relaunch
            }
            catch { add("space: graph persist deferred — \(error)") }
        }
    }

    /// Restore a persona's sealed space graph (async, under live presence) and apply it iff that
    /// persona is still current. No snapshot (first run) leaves the lazily-created fresh root.
    private func loadGraph(for persona: Profile?) {
        guard let persona, let vault = self.vault else { return }
        let handle = persona.handle
        let bio = biometric
        Task { @MainActor in
            let pole = await currentPoLE()
            guard pole.operate else { return }
            guard let data = try? vault.get(Self.graphKey, liveBiometric: bio, pole: pole),
                  let snap = try? JSONDecoder().decode(GraphSnapshot.self, from: data) else { return }
            guard currentPersona?.handle == handle else { return }   // user switched away meanwhile
            spaceRoots[handle] = AppSpace(dto: snap.space)
            defaultCaptureFolderID = snap.defaultCaptureFolderID
            defaultCaptureByType = snap.defaultCaptureByType ?? [:]
            graphRevision += 1
            add("space: restored persona graph from sealed snapshot ✓")
        }
    }

    /// Save a captured/imported blob: seal the bytes in the AtlasCore vault under live
    /// presence, then record it as an item in `space`. Returns nil on success or an error.
    /// Save into a space. `attested: true` (default) means this was CREATED/CAPTURED in Atlas:
    /// it gets a signed ProvenanceBundle (authorship + live attestation + ledger anchor) so it
    /// reads "Authored by a verified human." `attested: false` is for IMPORTS from elsewhere on
    /// the phone — stored, but honestly "origin not attested" (no verified-human authorship).
    @discardableResult
    func captureSave(name: String, data: Data, kind: String, to space: AppSpace, attested: Bool = true) async -> String? {
        var bundle: ProvenanceBundle?
        if attested {
            guard let authorship else { return "enrol first" }
            let pole = await currentPoLE()
            guard let attestation = AttestationSubsystem().attest(pole) else { return "no live presence" }
            let meta = CaptureMetadata(cameraIntrinsics: "atlas-capture", motion: "n/a",
                                       capturedAt: ISO8601DateFormatter().string(from: Date()),
                                       depthSummary: "none")
            bundle = try? Provenance.signCapture(content: data, depthMap: [], moireScore: 0, metadata: meta,
                                                 authorship: authorship, attestation: attestation,
                                                 beaconRound: beacon(), ledger: ledger)
        }
        if let err = await vaultAddFile(name: name, data: data, kind: kind) { return err }
        let saved = vaultFiles.last?.name ?? name
        if let bundle { attachProvenance(name: saved, bundle: bundle) }
        await MainActor.run { space.items.append(SpaceItem(vaultName: saved, kind: kind)); persistGraph() }
        return nil
    }

    /// Save content that ALREADY has a signed ProvenanceBundle (from the in-app camera) into
    /// a space: seal the bytes, attach the bundle (verified-human provenance), record the item.
    @discardableResult
    func saveBundle(_ content: Data, _ bundle: ProvenanceBundle, kind: String, to space: AppSpace) async -> String? {
        let name = "\(kind)-\(UUID().uuidString.prefix(6)).jpg"
        if let err = await vaultAddFile(name: name, data: content, kind: kind) { return err }
        let saved = vaultFiles.last?.name ?? name
        attachProvenance(name: saved, bundle: bundle)
        await MainActor.run { space.items.append(SpaceItem(vaultName: saved, kind: kind)); persistGraph() }
        return nil
    }

    /// Overwrite a vault file in place (same key) and re-attest it as an edit — for document
    /// saves. (C2PA edit-chaining is a later refinement; this re-signs the new bytes.)
    func updateVaultFile(_ name: String, data: Data) async -> String? {
        guard let vault else { return "enrol first" }
        let pole = await currentPoLE()
        guard pole.operate else { return "no live presence" }
        do { try vault.put(name, data, liveBiometric: biometric, pole: pole, beacon: beacon()) }
        catch { return "save failed: \(error)" }
        if let authorship, let attestation = AttestationSubsystem().attest(pole) {
            let meta = CaptureMetadata(cameraIntrinsics: "atlas-doc", motion: "n/a",
                                       capturedAt: ISO8601DateFormatter().string(from: Date()), depthSummary: "none")
            if let b = try? Provenance.signCapture(content: data, depthMap: [], moireScore: 0, metadata: meta,
                                                   authorship: authorship, attestation: attestation,
                                                   beaconRound: beacon(), ledger: ledger) {
                attachProvenance(name: name, bundle: b)
            }
        }
        if let i = vaultFiles.firstIndex(where: { $0.name == name }) {
            let o = vaultFiles[i]
            vaultFiles[i] = VaultFile(name: o.name, size: data.count, kind: o.kind, addedAt: o.addedAt)
        }
        return nil
    }

    /// Move an item reference between spaces (bytes stay sealed in the vault).
    func moveItem(_ item: SpaceItem, to dest: AppSpace, from src: AppSpace) {
        guard src.id != dest.id else { return }
        src.items.removeAll { $0.id == item.id }
        dest.items.append(item)
        persistGraph()
    }

    /// Release a vault file under live presence and write a temp copy for QuickLook.
    func tempURL(for name: String) async -> URL? {
        guard let data = await vaultOpenFile(name) else { return nil }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(name)
        do { try data.write(to: url); return url } catch { return nil }
    }

    /// Bumped whenever the space graph changes anywhere (a space/chat is created deep in the
    /// tree) so views that scan the WHOLE graph — the Chats tab, Office — reliably re-scan.
    @Published private(set) var graphRevision = 0

    /// Create a child space (pick a kind + name) under `parent`. Recursive — a space can nest
    /// spaces without limit. Persistence defaults from the kind.
    // MARK: - Market + Feed (device-local until the node swarm syncs them; signed under the
    // current persona's key exactly as the network versions will be)

    @Published private(set) var marketListings: [MarketListing] = []
    let feedStore = Feed()
    @Published private(set) var feedRevision = 0
    @Published private(set) var mySubscriptions: [Storefront.Subscription] = []

    /// List a work on the market under the CURRENT persona (signed; merchandising exposed, full
    /// product gated). Local until the node syncs the shared market.
    @discardableResult
    func listOnMarket(title: String, tags: [String], license: String, priceAtlas: Int,
                      access: AccessMode, blurb: String, description: String,
                      preview: String, contentRef: String) -> MarketListing? {
        guard let p = currentPersona,
              let l = try? Storefront.listOnMarket(
                workID: Primitives.H(Data("atlas/work".utf8), Data(title.utf8), p.handle),
                title: title, tags: tags, license: license, priceAtlas: priceAtlas, access: access,
                merch: Merchandising(blurb: blurb, description: description, preview: preview),
                fullContentRef: contentRef, signer: p.identity.keypair) else { return nil }
        marketListings.append(l)
        add("market: listed ‘\(title)’ (\(access.rawValue))")
        return l
    }

    /// Post to my feed (free reaches followers; paid needs a subscription to read).
    func postToFeed(caption: String, tier: PostTier, marketRef: String = "") {
        guard let p = currentPersona,
              let post = try? Feed.makePost(author: p.identity.keypair,
                                            ts: Int(Date().timeIntervalSince1970),
                                            caption: caption, tier: tier, marketRef: marketRef)
        else { return }
        try? feedStore.post(post)
        feedRevision += 1
    }

    func followAuthor(_ authorHex: String) {
        guard let p = currentPersona else { return }
        feedStore.follow(p.handle, author: authorHex)
        feedRevision += 1
    }

    func feedTimeline() -> [FeedPost] {
        guard let p = currentPersona else { return [] }
        return feedStore.timeline(p.handle, subscriptions: mySubscriptions,
                                  now: Int(Date().timeIntervalSince1970))
    }

    /// Subscribe the current persona to a creator (paid subscription — payment settles via the
    /// payment module at network launch; the grant object is the real one).
    func subscribe(to listing: MarketListing, days: Int = 30) {
        guard let p = currentPersona, let author = marketListings.first(where: { $0.id() == listing.id() }),
              let sub = try? Storefront.issueSubscription(
                issuer: currentPersonaKeypairIfAuthor(of: author) ?? p.identity.keypair,
                subscriber: p.handle, scope: author.author,
                expires: Int(Date().timeIntervalSince1970) + days * 86400) else { return }
        mySubscriptions.append(sub)
    }

    /// Local demo only: a subscription must be ISSUED by the creator's key. When the listing
    /// belongs to one of MY personas, sign with it; cross-user issuance arrives with the node.
    private func currentPersonaKeypairIfAuthor(of listing: MarketListing) -> HybridSign.Keypair? {
        personas.first(where: { $0.handle.map { String(format: "%02x", $0) }.joined() == listing.author })?
            .identity.keypair
    }

    /// AI-surfacing (pull, not push): given what the user NEEDS, return the market listings that
    /// genuinely MATCH, ranked by relevance — no ads, no pay-to-rank, only real matches. Mirrors the
    /// backend marketplace.surface() spirit. Used by the agent and the Market search/filter.
    func surfaceListings(for query: String, freeOnly: Bool = false, maxPrice: Int? = nil) -> [MarketListing] {
        func toks(_ s: String) -> Set<String> {
            Set(s.lowercased().split(whereSeparator: { !$0.isLetter && !$0.isNumber }).map(String.init))
        }
        let q = toks(query)
        let scored: [(Int, MarketListing)] = marketListings.compactMap { l in
            if freeOnly && l.access != .free { return nil }
            if let cap = maxPrice, l.access != .free, l.priceAtlas > cap { return nil }
            let hay = toks(l.title + " " + l.tags.joined(separator: " ") + " " + l.merch.blurb)
            let rel = q.isEmpty ? 1 : q.intersection(hay).count      // empty query = list all (for filter UI)
            return rel > 0 ? (rel, l) : nil
        }
        return scored.sorted { $0.0 > $1.0 }.map { $0.1 }
    }

    /// Render a document to a PROVENANCED PDF: sign the content hash with the current persona's key
    /// and stamp author + did:cid + hash + signature onto every page. Returns a temp URL to share.
    /// Anyone can recompute the hash and verify the signature — the PDF proves who made it, unaltered.
    func exportProvenancedPDF(title: String, body: String) -> URL? {
        guard let p = currentPersona else { return nil }
        let content = Data((title + "\n\n" + body).utf8)
        let hash = Primitives.H(Data("atlas/pdf/v1".utf8), content)
        let sig = (try? HybridSign.sign(p.identity.keypair, hash)) ?? Data()
        func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
        let did = DidCid.didFor(p.identity.keypair.publicKey)
        let pdf = PDFExport.make(title: title, body: body,
                                 authorLabel: username.isEmpty ? "this persona" : username,
                                 did: did, contentHashHex: hex(hash), signatureHex: hex(sig))
        let safe = String(title.replacingOccurrences(of: "/", with: "-").prefix(40))
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("\(safe.isEmpty ? "document" : safe).pdf")
        guard (try? pdf.write(to: url)) != nil else { return nil }
        add("exported provenanced PDF — signed by \(username.isEmpty ? "this persona" : username)")
        return url
    }

    // MARK: - Sensitive records (records assembly surface)

    /// One sensitive record in the app: a sealed blob at the HIGH-PROTECTION tier, its space policy
    /// (roles + quorum + tamper-evident access log), and the owner-held content key. (In a hardened
    /// build the content key is sealed to the persona's enclave; here it's held in the live session.)
    struct SensitiveRecordEntry: Identifiable {
        let id = UUID()
        let title: String
        let kind: String                 // "text" | "pdf" | "image" | "file"
        let space: SensitiveSpaceNS.SensitiveSpace
        let contentKey: Data
    }
    @Published private(set) var sensitiveRecords: [SensitiveRecordEntry] = []

    private func recordRound() -> Int { serverBeaconRound > 0 ? serverBeaconRound : Int(Date().timeIntervalSince1970) }

    /// Create a sensitive record from ANY bytes (typed text, an imported PDF/image/document, or a
    /// vault file): seal it, open a space with you as sole GOVERNOR, start its tamper-evident log.
    /// Records assembly end-to-end — the space policy gates WHO, the records layer gates WHEN.
    @discardableResult
    func createSensitiveRecord(title: String, data: Data, kind: String) -> Bool {
        guard let p = currentPersona, !data.isEmpty else { return false }
        let ck = Primitives.randomBytes(32)
        guard let rec = try? Records.sealRecord(data, contentKey: ck) else { return false }
        let policy = SpaceGovernance.SpacePolicy.genesis(spaceID: Primitives.H(Data("atlas/record".utf8), Data(title.utf8), p.handle),
                                                         creator: p.identity.keypair.publicKey)
        let space = SensitiveSpaceNS.SensitiveSpace(policy: policy, record: rec, log: Records.AccessLog())
        sensitiveRecords.insert(SensitiveRecordEntry(title: title, kind: kind, space: space, contentKey: ck), at: 0)
        add("sensitive record created — “\(title)” (\(kind) · sealed · high-protection tier)")
        return true
    }

    /// Convenience for typed text.
    func createSensitiveRecord(title: String, content: String) {
        createSensitiveRecord(title: title, data: Data(content.utf8), kind: "text")
    }

    /// Open your own record — role-gated (you're the governor ≥ reader) AND logged. Returns the raw
    /// sealed bytes (the caller renders by `kind`: text / PDF / image / file).
    func openSensitiveRecordData(_ entry: SensitiveRecordEntry) -> Data? {
        guard let p = currentPersona,
              let plain = try? SensitiveSpaceNS.openOwn(entry.space, member: p.identity.keypair.publicKey,
                                                        contentKey: entry.contentKey, nowRound: recordRound())
        else { return nil }
        objectWillChange.send()   // the access log mutated
        return plain
    }

    /// Text convenience for a "text" record.
    func openSensitiveRecord(_ entry: SensitiveRecordEntry) -> String? {
        openSensitiveRecordData(entry).map { String(decoding: $0, as: UTF8.self) }
    }

    // MARK: - PoLE receipts wallet + paid attention ("the game of living")

    @Published private(set) var presenceReceipts: [PresenceReceiptNS.PresenceReceipt] = []
    @Published private(set) var attentionEarnings: Int = 0
    @Published private(set) var attentionOffers: [Attention.AttentionOffer] = []
    private let attentionLedger = Attention.AttentionLedger()
    private static let demoStoreKp = try! HybridSign.keypair(fromSeed: Primitives.H(Data("atlas/demo-store".utf8)))

    private var lastPresenceReceiptAt: TimeInterval = 0
    private static let presenceReceiptWindowS: Double = 30   // auto-mint at most one receipt per 30 s

    /// Total attested presence (seconds) across receipts in the wallet.
    var totalPresenceSeconds: Int { presenceReceipts.reduce(0) { $0 + max(0, $1.windowEnd - $1.windowStart) } }
    /// Whether PoLE is live-minting right now (the clock is running and presence holds).
    var poleMinting: Bool { running && presenceLive }

    /// AUTOMATIC — called on each live PoLE tick. Mints a receipt once per window, committing to the
    /// fused live entropy (never raw signals). The user does nothing; presence attests itself while
    /// the app stays alive on location + sensors. Persona-signed; a wearable co-sign = multi-stream.
    func autoMintPresenceReceipt() {
        guard let p = currentPersona else { return }
        let now = Date().timeIntervalSince1970
        let start = lastPresenceReceiptAt > 0 ? lastPresenceReceiptAt : now - Self.presenceReceiptWindowS
        guard now - start >= Self.presenceReceiptWindowS else { return }   // throttle: one per window
        let commit = Primitives.H(Data("atlas/pole-commit".utf8), ambient.fusedWindow())
        if let r = try? PresenceReceiptNS.mintReceipt(signers: [p.identity.keypair], subject: p.handle,
                                                      windowStart: Int(start), windowEnd: Int(now), poleCommit: commit) {
            presenceReceipts.insert(r, at: 0)
            if presenceReceipts.count > 200 { presenceReceipts.removeLast(presenceReceipts.count - 200) }
            lastPresenceReceiptAt = now
        }
    }

    /// Demo attention offers (stores that pay you to look). In production these arrive from verified
    /// organizations via the node; here a demo store issues a few so the loop is visible.
    func loadAttentionOffers() {
        let now = Int(Date().timeIntervalSince1970)
        let catalogue = [("Fair-trade coffee", 3), ("Repairable phone", 5), ("Local bakery box", 2)]
        attentionOffers = catalogue.compactMap { item in
            try? Attention.makeOffer(Self.demoStoreKp, productID: Data(item.0.utf8),
                                     reward: item.1, windowStart: now - 300, windowEnd: now + 3600)
        }
    }

    /// "View & earn": looking at the product IS attention — spend a RECENT auto-minted presence
    /// receipt (proof you're genuinely live now) to claim, paid once. No manual signing: if PoLE
    /// isn't live you have no recent receipt and can't earn — which is exactly the anti-bot property.
    @MainActor
    func viewAndEarn(_ offer: Attention.AttentionOffer) async -> String {
        guard let p = currentPersona else { return "No active persona." }
        // a recent, auto-minted presence receipt whose window overlaps the offer window
        guard let r = presenceReceipts.first(where: {
            !($0.windowEnd < offer.windowStart || $0.windowStart > offer.windowEnd)
        }) else {
            return poleMinting ? "One moment — recording your presence…"
                               : "You must be present (PoLE live) to earn. Presence records itself on the clock."
        }
        guard let claim = try? Attention.claimAttention(p.identity.keypair, offer: offer, receipt: r) else {
            return "Could not build claim."
        }
        do {
            let reward = try attentionLedger.redeem(offer, claim)
            attentionEarnings += reward
            add("earned \(reward) ⏣ for viewing \(String(decoding: offer.productID, as: UTF8.self))")
            return "Earned \(reward) ⏣"
        } catch {
            return "Already earned from this offer."
        }
    }

    /// Start (or reopen) a direct chat with `name` — the Comms tab's "+" and the Contacts
    /// "Message" action. One chat per name at the root; the person is a member.
    @discardableResult
    func startChat(with name: String) -> AppSpace? {
        guard let root = currentRoot else { return nil }
        if let existing = root.allChats().first(where: { $0.name == name }) { return existing }
        let chat = createSpace(kind: .chat, name: name, in: root)
        if !chat.members.contains(name) { chat.members.append(name); persistGraph() }
        return chat
    }

    @discardableResult
    func createSpace(kind: SpaceKind, name: String, in parent: AppSpace) -> AppSpace {
        let n = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let child = AppSpace(name: n.isEmpty ? kind.label : n, kind: kind,
                             persistence: kind.defaultPersistence)
        parent.children.append(child)
        graphRevision += 1
        add("space: created ‘\(child.name)’ (\(kind.label) · \(child.persistence.label))")
        persistGraph()
        return child
    }

    /// Whether a profile has verified its identity (Market/economy access gate).
    func isVerified(_ profile: Profile) -> Bool { verifiedProfiles.contains(profile.handle) }

    /// Real-ID verified on-device. Two ASSURANCE TIERS: "chip" (eID/ePassport NFC — the document
    /// cryptographically proves itself) and "barcode" (driver's-licence PDF417 — document-STATED,
    /// a barcode can be printed by anyone; honest lower tier). Stores NO document data — only the
    /// verified mark + tier on this persona (+ birth year for the age credential).
    func markRealIDVerified(_ profile: Profile, birthYear: Int?, method: String = "chip") {
        verifiedProfiles.insert(profile.handle)
        UserDefaults.standard.set(method, forKey: "atlas.idtier.\(profile.username)")
        if let y = birthYear {
            UserDefaults.standard.set(y, forKey: "atlas.birthyear.\(profile.username)")
        }
        add("Real-ID verified (\(method)) — persona: \(profile.username)")
    }

    func realIDTier(_ profile: Profile) -> String? {
        isVerified(profile) ? (UserDefaults.standard.string(forKey: "atlas.idtier.\(profile.username)") ?? "chip") : nil
    }

    /// Whether a chip Real-ID's ISSUING COUNTRY was cryptographically confirmed (the document-signer
    /// chained to a trusted ICAO CSCA). False = the chip was authentic (data intact + validly signed)
    /// but the issuer chain wasn't confirmed (no CSCA master list provisioned). Honest tier display.
    func realIDIssuerConfirmed(_ profile: Profile) -> Bool {
        UserDefaults.standard.bool(forKey: "atlas.realid.issuerConfirmed.\(profile.username)")
    }
    /// Convenience for the active profile.
    var isCurrentProfileVerified: Bool { currentPersona.map { isVerified($0) } ?? false }

    /// Real-ID verification is NOT available yet — the gov-document (ePassport/NFC) verifier is a
    /// later slice (needs the paid entitlement + CoreNFC read → the AtlasCore RealID verifier).
    /// This deliberately does NOT mark anything verified: nothing may display "verified" until a
    /// genuine verification has actually happened. (Was a stub that flipped the flag with no
    /// verification — a false claim; removed.)
    func verifyCurrentProfile() {
        add("Real-ID verification is not available yet — government-document verification arrives with the eID reader. Nothing has been marked verified.")
    }

    /// One file in the vault, for the browser. Metadata only — the bytes stay sealed
    /// at rest and are released per-open under live presence.
    struct VaultFile: Identifiable, Equatable {
        var id: String { name }
        let name: String
        let size: Int
        let kind: String        // "image" | "pdf" | "text" | "file"
        let addedAt: Date
    }
    @Published private(set) var vaultFiles: [VaultFile] = []
    /// Per-persona satellite stores — swapped on `switchPersona` so NOTHING persona-scoped
    /// bleeds across personas (files, votes, claimed name, default-capture folder). Mirrors
    /// `historyByPersona`. (The space tree itself is already keyed per handle in `spaceRoots`.)
    private var vaultFilesByPersona: [Data: [VaultFile]] = [:]
    private var votesByPersona: [Data: [Social.Vote]] = [:]
    private var claimedNameByPersona: [Data: String] = [:]
    private var defaultCaptureFolderByPersona: [Data: UUID] = [:]
    private var defaultCaptureByTypeByPersona: [Data: [String: UUID]] = [:]

    // MARK: - provenanced content + sybil-resistant views

    /// Provenance bundle carried per authored vault item. Live-captured content gets a real bundle;
    /// imported files get none (honest: "stored, origin not attested" — no false authorship claim).
    /// Verified on OPEN against the decrypted bytes; a stored verdict would be meaningless — the
    /// bytes are what prove it.
    private var provenance: [String: ProvenanceBundle] = [:]

    /// Sybil-resistant view registry: item name -> set of distinct VIEWER NULLIFIERS. A view is a
    /// PoLE-gated event counted by an unlinkable per-(viewer,item) nullifier, so we count distinct
    /// verified humans WITHOUT identifying them (real reach, no surveillance, no bot inflation).
    /// Local here; a network tally aggregates nullifiers across nodes (downstream of the node network).
    private var viewNullifiers: [String: Set<Data>] = [:]

    /// Attach the live-capture provenance bundle to a stored item (called by the capture flow).
    func attachProvenance(name: String, bundle: ProvenanceBundle) { provenance[name] = bundle }

    /// Re-verify an item's provenance against its decrypted bytes (nil if it carries none).
    func provenanceVerdict(for name: String, content: Data) -> ProvenanceVerdict? {
        provenance[name].map { Provenance.verify($0, content: content, ledger: ledger) }
    }

    /// Register a view by THIS verified human (a nullifier) and return the distinct-viewer count.
    /// One human counts once per item; the nullifier can't be tied back to them.
    @discardableResult
    func registerView(of name: String) -> Int {
        guard let root = identity?.rootHandle else { return viewNullifiers[name]?.count ?? 0 }
        let itemKey = Primitives.H(Data("atlas/view-item".utf8), Data(name.utf8))
        let nullifier = Primitives.H(Data("atlas/view-nullifier".utf8), root, itemKey)
        viewNullifiers[name, default: []].insert(nullifier)
        return viewNullifiers[name]!.count
    }

    // Hardware factors (models today; real R10 / YubiKit / Lexar swap in):
    let ambient = AmbientSensorSource()
    let yubikey = YubiKeyBio()
    let ring = RingProbe()                  // the REAL R10 — its live pulse is the presence signal
    let recoveryKP = HybridKEM.generateKeypair()

    /// The enrolled biometric template the Enclave model matches (real Face ID on
    /// device releases the SE-sealed secret). Same value used as the live biometric.
    let biometric = Data(repeating: 7, count: 32)

    private let sphincs: SphincsProvider = PlaceholderSphincs()
    // ONE persistent ambient source so the change-detector keeps its snapshot history
    // across ticks (a fresh source every call has nothing to diff -> always "absent").
    private lazy var ambientSource: SignalSource = ambient.asSignalSource()
    // Presence comes from the RING PULSE, not phone motion. The ring's PPG oscillation
    // gates it: a live pulse -> non-empty window -> present; a removed/flat ring ->
    // empty window -> ABSENT (fail-closed). Presence/timing only — never key material.
    private lazy var ringSource: SignalSource = ClosureSignalSource(
        kind: "ring", simulated: false, channels: ["ring-ppg"], liveFloor: 2
    ) { [weak self] in self?.ring.presenceWindow() ?? Data() }
    // FUSION (not a swap): the ambient stream is ALWAYS in the mix; a connected
    // wearable ADDS its signal on top. The per-tick window = ambient snapshot ++ the
    // ring's PPG presence window, so when the ring is on its live pulse contributes
    // extra entropy + liveness, and when it's off the source is ambient-only (never
    // fails just because there's no ring). Change-detecting over the COMBINED window;
    // timing/presence only, never key material.
    private lazy var fusedSource: SignalSource = ChangeDetectingSignalSource(
        kind: "ambient+wearable", simulated: true,
        channels: AmbientSensorSource.channels + ["ring-ppg"], liveFloor: 2
    ) { [weak self] in
        guard let self else { return Data() }
        return self.ambient.fusedWindow() + self.ring.presenceWindow()
    }
    private let livenessGate = LivenessGate()
    private var drandRound = Data(count: 8)
    private var panicVault: PanicVault?     // duress: panic code -> decoy; normal -> real
    // ALWAYS the REAL hardware Secure Enclave — Atlas requires an SE device. No model
    // fallback in the running app; enrolment fails closed if the SE is absent (see
    // provision()). The ModelEnclave survives ONLY as the AtlasCore CI/parity test
    // double — never used by the running app.
    private let enclave: BiometricEnclave = SecureEnclaveStore()
    private var enrolWitnessSig: Data?      // YubiKey's fingerprint-gated signature over the enrolment

    // Distributed recovery: tskSeed = userPart XOR serverPart.
    //  - userPart: your POSSESSION — held whole on your USB AND your wallet (phone).
    //    EITHER one is enough (a lost single factor recovers nothing on its own — it's
    //    only half the seed).
    //  - serverPart: split k-of-N across the server nodes, released ONLY by the full
    //    in-person ceremony: you physically appear at a recovery server, a human verifies
    //    your live presence, your Face ID makes a server-side signature, AND you give your
    //    password. Any one missing -> the server share stays locked.
    @Published private(set) var recoveryArmed = false
    private var recUserPart: Data?                      // whole userPart (on USB + wallet; either suffices)
    private var recServerShares: [Shamir.Share] = []    // serverPart split k-of-N across the nodes
    private var recoveryPasswordHash: Data?             // gates the server-side release (name+password record)

    init() {
        AtlasFlags.logHonesty()
        // Clear any stored operator/dev node URL so an open build never carries a baked-in relay;
        // the user sets their own node in Settings ▸ Node.
        let stored = UserDefaults.standard.string(forKey: "atlas.node.url") ?? ""
        if stored.contains("192.168.") || stored.contains("179.237.") || stored.contains("clockwork-tree.com") {
            UserDefaults.standard.removeObject(forKey: "atlas.node.url")
            nodeURL = ""
        }
        // Default web search through the node's /search proxy (over HTTPS) when no explicit searx
        // URL is set — so the phone never needs to reach an HTTP searx port directly (ATS-blocked).
        WebLibrary.nodeSearchBase = nodeSearchURL.isEmpty ? (nodeURL.isEmpty ? nil : nodeURL) : nodeSearchURL
        loadPanicContacts()
    }

    private func add(_ s: String) { log.append(s); DevLog.shared.info("session", s) }

    /// Internal passthrough so a view (e.g. a blocked intent gesture) can write to the
    /// shared session log without exposing the underlying store.
    func note(_ s: String) { add(s) }

    // MARK: - the one enrolment ritual

    /// Face ID + password + button + live presence -> build the identity, seal the
    /// enrolment secret, establish the epoch, register the YubiKey, and open the
    /// vault. On success every feature unlocks against THIS identity + presence.
    func provision(password: String, panicCode: String, buttonDoubleClicked: Bool) async throws {
        // HARD REQUIREMENT: a real Secure Enclave. The identity root + vault are sealed to
        // it — no SE, no enrolment (fail closed; no model fallback in production).
        guard SecureEnclaveStore.isAvailable else {
            throw NSError(domain: "Atlas", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "Atlas requires a device with a Secure Enclave."])
        }
        // Presence source — FUSION, not a swap. The ambient stream is always the
        // running mix; a live ring pulse ADDS its biological signal + liveness on top
        // (see `fusedSource`). A present ring raises the recorded tier to .ring; with
        // no ring it's .ambient — but enrol never fails just for lack of a ring.
        enrolTier = ring.pulsePresent ? .ring : .ambient
        enrolProgress = [enrolTier == .ring
            ? "① ambient mode + live ring pulse"
            : "① ambient mode — capturing sensor entropy"]
        // Prime the FRESH-PER-TICK ambient source: it's normally pulled once per
        // ratchet tick, so before the one-shot enrol sample we take several live
        // snapshots to give the change-detector real motion to gate on.
        for _ in 0..<10 {
            await ambient.refreshSnapshot()
            try? await Task.sleep(nanoseconds: 120_000_000)
        }
        let ceremony = EnrollmentCeremony(sphincs: sphincs)
        let result = try await ceremony.enrol(signalSource: fusedSource,
                                               password: password,
                                               buttonDoubleClicked: buttonDoubleClicked,
                                               forensicWindow: true)
        enrolProgress = ["✓ \(enrolTier.label) + Face ID + password + button"]
        self.identity = result.identity
        self.enrolmentSecret = result.enrollmentSecret

        let author = result.identity.child(.authorship)   // identity-level authorship (Device, continuity)
        // Default persona = your first operating identity, derived off the System-ID with its
        // OWN full stack. Base is ANONYMOUS (a pseudonym); Real-ID is a separate, optional,
        // one-per-person slot. You act AS a persona, never the raw System-ID; make more any time.
        let defaultPersona = try? result.identity.profile(username.isEmpty ? "me" : username, tier: .anonymous)
        self.currentPersona = defaultPersona
        self.personas = defaultPersona.map { [$0] } ?? []
        self.device = Device(name: "iPhone", identity: result.identity,
                             devKey: Primitives.randomBytes(32),
                             bootstrapTunnelKey: Primitives.randomBytes(32),
                             enclave: enclave)

        // TWO SEPARATE THINGS (per DECISIONS.md) — do not conflate:
        //  • drand / beacon = the PUBLIC timekeeper. Just a number everyone agrees on; it
        //    gives the epoch ID (which epoch we're in) + the attestation timestamp. The
        //    public epoch ID is what lets the group co-derive one LK per epoch. NEVER a key.
        //  • the EPOCH KEY = a SECRET, global value derived from population-scale liveness
        //    timing + best-available RNG, aggregated in the cloud (no single node holds or
        //    can forge it). It is presence-gated (sealed to the enrolment secret) and WRAPS
        //    the private LK — a present, enrolled device unwraps it to unlock the LK.
        //    PoC STUB: modeled as a fresh secret here; the real value is the global cloud
        //    aggregation. What matters for the model: it is SECRET + presence-released, NOT
        //    the public beacon (wrapping the LK under a public value would void its secrecy).
        let eb = LocalBeacon().round(at: 0)          // drand stand-in — PUBLIC timekeeper only
        self.epochBeacon = eb
        self.drandRound = eb.drandRound()                  // public epoch id (from the beacon)
        let epochKey = Primitives.randomBytes(32)    // SECRET epoch key (stub for the global cloud value)
        self.epochKeyValue = epochKey
        self.wrappedEpochKey = try device!.wrapEpochKey(epochKey, drandRound: drandRound)   // presence-gated

        // 1-PHONE MODE: generate THIS device's own live LK from local entropy so the living
        // engine (ratchet + presence gate + LK) runs SOLO on the ambient multi-sensor mix +
        // internal noise — it does NOT wait for a second phone. When a peer later comes
        // online, the co-derived GROUP LK replaces this one (for shared messaging). Wrapped
        // under the presence-gated epoch key, exactly like the two-phone co-derived path.
        self.epochLK = Primitives.randomBytes(32)
        if let soloLK = self.epochLK,
           let wrappedLK = try? Presence.wrapLK(soloLK, epochKey: epochKey, drandRound: drandRound) {
            self.epoch = (self.wrappedEpochKey!, wrappedLK)
        }

        enrolProgress.append("✓ identity + secret epoch key (presence-gated) + LK binding")

        // Open the vault + media store against the CURRENT PERSONA (its own per-persona vault
        // key), falling back to the identity authorship child if no persona derived.
        openVault(for: defaultPersona, fallback: author)
        loadGraph(for: defaultPersona)   // restore a returning user's sealed space graph (#18)
        openLand(for: defaultPersona)
        enrolProgress.append("✓ secure vault opened (persona: \(currentPersona?.username ?? "—"))")

        // Duress slice: the panic code opens a DECOY vault (surface identical to the
        // real one); the normal password opens the real one. Zeroize-on-suspicion
        // destroys the real key (a permanent brick), the decoy survives.
        if !panicCode.isEmpty {
            let pv = try PanicVault(normalCode: Data(password.utf8), panicCode: Data(panicCode.utf8)) { reason in
                print("[ATLAS] zeroize-on-suspicion: \(reason)")
            }
            try pv.seedDecoy("wallet", Data("DECOY: small balance, no keys".utf8))
            self.panicVault = pv
            // Arm the unlock-code gate: normal code (password) opens real; panic code triggers
            // the chosen duress response. This is what makes the code demanded on every unlock a
            // real coercion channel, not just a lock (Axiom 5).
            configureDuress(normalCode: password, panicCode: panicCode)
        }

        armRecovery(seed: result.tskSeed, password: password)
        setupRecoveryShares(tskSeed: result.tskSeed)   // 2-of-n shards: phone SE · USB · contact · server
        enrolProgress.append("✓ recovery armed (USB + phone + nodes)")

        // Seed presence live: the user just proved presence (Face ID + ceremony).
        for _ in 0..<20 { livenessGate.update(pSGivenLive: 0.97, pSGivenNotLive: 0.05) }
        enrolProgress.append("✓ identity built — next: sign it with your YubiKey")
        add("provisioned — identity + epoch key + vault + recovery bound. Awaiting YubiKey witness.")
    }

    /// EXPLICIT wizard step: the YubiKey Bio WITNESSES the enrolment. Present the key
    /// and touch its fingerprint sensor -> a fingerprint-gated signature over the
    /// identity+epoch binding (model YubiKeyBio — real signature, fingerprint simulated;
    /// real YubiKit tap later). Enrolment can't go live without it.
    func witnessEnrolmentWithYubiKey() throws {
        guard let author = authorship else { throw EnrolError.noIdentityYet }
        let enrolReq = HighStakesRequest(action: "enrol",
                                         context: Primitives.H(author.handle, drandRound),
                                         challenge: Primitives.randomBytes(16))
        let sig = try yubikey.authorize(enrolReq, fingerprintMatched: true)
        self.enrolWitnessSig = sig
        add("YubiKey signed the enrolment (witness) \(sig.prefix(4).map { String(format: "%02x", $0) }.joined())…")
        enrolProgress.append("✓ YubiKey signed your enrolment")
    }

    /// Whether the YubiKey has witnessed this enrolment (gates go-live).
    var enrolmentWitnessed: Bool { enrolWitnessSig != nil }
    /// Short hex of the witness signature, for the wizard to show.
    var enrolWitnessHex: String {
        enrolWitnessSig?.prefix(6).map { String(format: "%02x", $0) }.joined() ?? ""
    }

    enum EnrolError: Error { case noIdentityYet }

    /// Finish the wizard: go live (unlock the app + bring the group session online).
    /// Called at the last setup step, after the USB recovery share is saved.
    func goLive() {
        // YubiKey witness SUSPENDED (Bio has no NFC; iOS FIDO2 is NFC/Lightning only).
        // Re-add `enrolWitnessSig != nil` to this guard once an NFC key is wired.
        guard identity != nil, !enrolled else { return }
        enrolled = true
        PresenceUnlock.onUnlock(&presenceUnlock, tier: .max); refreshEffectiveTier()   // #42
        persistSession()   // seal the session for relaunch restore (#37)
        add("Live — session online.")
        startRatchet()   // 1-phone living engine: ambient multi-sensor + ratchet + LK run SOLO now
        // Integrate into the wider ATLAS network: the epoch key is a population-scale liveness
        // value aggregated across the whole network (not a pairwise value). connectGroup() is
        // the CURRENT stand-in for that network integration — a relay demo, not the real
        // population-scale fabric yet. It is NOT "for messaging"; messaging is just one thing
        // the network integration enables.
        connectGroup()
    }

    /// Is the identity provisioned but not yet live (mid-wizard)?
    var provisioned: Bool { identity != nil && !enrolled }

    /// Live-presence probe: is the RING showing a live pulse right now? Fail-closed —
    /// no ring / no pulse -> false. Drives the wizard's ring step and the presence gate.
    func detectPresence() async -> Bool {
        return ((try? ringSource.sample())?.present) ?? false
    }

    // MARK: - vault file browser

    /// Add a file to the vault: sealed under live presence (biometric + ring PoLE),
    /// provenance-stamped. Returns nil on success, or an error string to show.
    func vaultAddFile(name: String, data: Data, kind: String) async -> String? {
        guard let vault else { return "enrol first" }
        let poLE = await currentPoLE()
        guard poLE.operate else { return "no live pulse — wear your ring to unlock the vault" }
        let unique = uniqueVaultName(name)
        do {
            try vault.put(unique, data, liveBiometric: biometric, pole: poLE, beacon: beacon())
            vaultFiles.append(VaultFile(name: unique, size: data.count, kind: kind, addedAt: Date()))
            add("vault: added ‘\(unique)’ (\(data.count) B) — sealed under live presence ✓")
            return nil
        } catch { return "add failed: \(error)" }
    }

    /// Open a file: release it from the vault under live presence. Returns the
    /// decrypted bytes, or nil (with a logged reason) if the gate refused.
    func vaultOpenFile(_ name: String) async -> Data? {
        guard let vault else { return nil }
        let poLE = await currentPoLE()
        guard poLE.operate else { add("vault: open refused — no live pulse (wear your ring)"); return nil }
        do {
            let data = try vault.get(name, liveBiometric: biometric, pole: poLE)
            add("vault: opened ‘\(name)’ under live presence ✓")
            return data
        } catch { add("vault: open failed — \(error)"); return nil }
    }

    /// Delete a file from the vault (destroy the ciphertext at rest on this device).
    func vaultDeleteFile(_ name: String) {
        vault?.delete(name)
        vaultFiles.removeAll { $0.name == name }
        add("vault: deleted ‘\(name)’")
    }

    private func uniqueVaultName(_ name: String) -> String {
        guard vaultFiles.contains(where: { $0.name == name }) else { return name }
        let ext = (name as NSString).pathExtension
        let base = (name as NSString).deletingPathExtension
        var n = 2
        while vaultFiles.contains(where: { $0.name == (ext.isEmpty ? "\(base) \(n)" : "\(base) \(n).\(ext)") }) { n += 1 }
        return ext.isEmpty ? "\(base) \(n)" : "\(base) \(n).\(ext)"
    }

    // MARK: - TSK recovery shards (2-of-n: phone SE + USB, optional contact + server)
    //
    // The seed is split at enrol into shards under the anti-all-institutional invariant: the phone
    // shard seals into the SE; USB / contact / server shards wait (SE-sealed) for export. Any ONE
    // shard is information-theoretically nothing; a contact's shard is an opaque blob (silent
    // guardian — no name, no hint what it recovers); the server shard is useless without a
    // personal shard (invariant enforced at reconstruction too). Any 2 shards recover the identity.

    private static let shardStoreKey = "atlas.tsk.shards.sealed.v1"     // label -> sealed shard
    private static let shardSealLabel = Data("atlas/tsk-shard".utf8)

    @Published private(set) var shardLabels: [String] = []

    /// Split the genesis seed into recovery shards (called once, at enrol, while the seed exists).
    func setupRecoveryShares(tskSeed: Data) {
        // TWO-TIER: Shamir(your-half over phone·USB·contact) AND Shamir(server-half over nodes),
        // both mandatory. The server side only ever holds server_half → it can NEVER reconstruct
        // without a threshold of YOUR holders (structural, not a policy check). See TSKTwoTier.
        let (userHolders, serverHolders) = TSKTwoTier.defaultHolders()
        guard let upol = try? ThresholdSeal.ThresholdPolicy(n: 3, m: 2),
              let spol = try? ThresholdSeal.ThresholdPolicy(n: 3, m: 2),
              let shares = try? TSKTwoTier.split(seed: tskSeed, userHolders: userHolders,
                                                 serverHolders: serverHolders,
                                                 userPolicy: upol, serverPolicy: spol) else { return }
        var store: [String: String] = [:]
        func stash(_ side: String, _ s: TSKTwoTier.TSKShare) {
            let payload: [String: Any] = ["v": 2, "side": side, "holder": s.holder.label,
                                          "institutional": s.holder.institutional,
                                          "share": s.share.encode().base64EncodedString(),
                                          "un": upol.n, "um": upol.m, "sn": spol.n, "sm": spol.m]
            guard let data = try? JSONSerialization.data(withJSONObject: payload) else { return }
            store["\(side):\(s.holder.label)"] = enclave.seal(data, label: Self.shardSealLabel).base64EncodedString()
        }
        shares.userShares.forEach { stash("user", $0) }
        shares.serverShares.forEach { stash("server", $0) }
        UserDefaults.standard.set(store, forKey: Self.shardStoreKey)
        shardLabels = Array(store.keys).sorted()
        add("recovery: two-tier — your-half 2-of-3 (phone·USB·contact) AND server-half 2-of-3 (nodes)")
    }

    func loadShardLabels() {
        let store = UserDefaults.standard.dictionary(forKey: Self.shardStoreKey) as? [String: String] ?? [:]
        shardLabels = Array(store.keys).sorted()
    }

    /// Export one shard (Face ID — the SE release gates it). Returns the opaque shard file bytes.
    func exportShard(_ label: String) -> Data? {
        let store = UserDefaults.standard.dictionary(forKey: Self.shardStoreKey) as? [String: String] ?? [:]
        guard let sealedB64 = store[label], let sealed = Data(base64Encoded: sealedB64) else { return nil }
        return enclave.release(sealed, liveSample: biometric, label: Self.shardSealLabel)
    }

    /// Remove a shard from this phone after it has been exported (moved to its holder).
    func removeShard(_ label: String) {
        var store = UserDefaults.standard.dictionary(forKey: Self.shardStoreKey) as? [String: String] ?? [:]
        store.removeValue(forKey: label)
        UserDefaults.standard.set(store, forKey: Self.shardStoreKey)
        shardLabels = Array(store.keys).sorted()
        add("recovery: shard ‘\(label)’ moved off this phone")
    }

    /// Rebuild the identity from ANY 2 shard files (the recovery path on a new/wiped phone).
    /// The anti-all-institutional invariant is enforced inside reconstructTSK.
    func recoverFromShards(_ shardFiles: [Data]) throws {
        // Two-tier reconstruct: gather YOUR-half shares AND server-half shares; need a threshold
        // of each. Server shares alone can never rebuild the seed (they only carry server_half).
        var userShares: [TSKTwoTier.TSKShare] = []
        var serverShares: [TSKTwoTier.TSKShare] = []
        var un = 3, um = 2, sn = 3, sm = 2
        for f in shardFiles {
            guard let obj = try? JSONSerialization.jsonObject(with: f) as? [String: Any],
                  let holder = obj["holder"] as? String,
                  let inst = obj["institutional"] as? Bool,
                  let shareB64 = obj["share"] as? String,
                  let raw = Data(base64Encoded: shareB64) else { continue }
            un = (obj["un"] as? Int) ?? un; um = (obj["um"] as? Int) ?? um
            sn = (obj["sn"] as? Int) ?? sn; sm = (obj["sm"] as? Int) ?? sm
            let sh = TSKTwoTier.TSKShare(holder: ThresholdSeal.Custodian(label: holder, institutional: inst),
                                         share: Shamir.Share.decode(raw))
            if (obj["side"] as? String) == "server" { serverShares.append(sh) } else { userShares.append(sh) }
        }
        let upol = try ThresholdSeal.ThresholdPolicy(n: un, m: um)
        let spol = try ThresholdSeal.ThresholdPolicy(n: sn, m: sm)
        let seed = try TSKTwoTier.reconstruct(userShares: userShares, serverShares: serverShares,
                                              userPolicy: upol, serverPolicy: spol)
        let tree = try IdentityTree.build(tskSeed: seed, sphincs: sphincs)
        self.identity = tree
        let defaultPersona = try? tree.profile(username.isEmpty ? "me" : username, tier: .anonymous)
        self.currentPersona = defaultPersona
        self.personas = defaultPersona.map { [$0] } ?? []
        setupRecoveryShares(tskSeed: seed)          // re-split on the new phone
        persistSession()
        let author = tree.child(.authorship)
        openVault(for: currentPersona, fallback: author)
        openLand(for: currentPersona)
        for _ in 0..<20 { livenessGate.update(pSGivenLive: 0.97, pSGivenNotLive: 0.05) }
        enrolled = true
        add("identity RECOVERED from 2 shards — welcome back")
        startRatchet()
        connectGroup()
        sendPushRegistration()
    }

    // MARK: - Session restore (device-local persistence across app launches, #37)
    //
    // The identity's secret state is sealed under the Secure Enclave (release = the OS Face ID
    // prompt) and stored with the persona names + each persona's at-rest vault blob (already
    // ciphertext — "ciphertext anywhere"). On relaunch: Face ID -> restore the tree -> re-derive
    // the personas (deterministic from the System-ID) -> reopen the persisted vault -> live.

    private static let restoreIdentityKey = "atlas.session.identity.sealed.v1"
    private static let restoreUsernamesKey = "atlas.session.personas.v1"
    private static let restoreCurrentKey = "atlas.session.current.v1"
    private static let restoreSealLabel = Data("atlas/session-identity".utf8)

    /// A sealed session exists on this device (show "Unlock" instead of enrol).
    var canRestore: Bool { UserDefaults.standard.data(forKey: Self.restoreIdentityKey) != nil }

    private func persistSession() {
        guard let identity else { return }
        let sealed = enclave.seal(identity.exportState(), label: Self.restoreSealLabel)
        guard !sealed.isEmpty else { return }
        UserDefaults.standard.set(sealed, forKey: Self.restoreIdentityKey)
        UserDefaults.standard.set(personas.map { $0.username }, forKey: Self.restoreUsernamesKey)
        UserDefaults.standard.set(currentPersona?.username ?? "", forKey: Self.restoreCurrentKey)
    }

    private func clearPersistedSession() {
        let d = UserDefaults.standard
        for name in (d.stringArray(forKey: Self.restoreUsernamesKey) ?? []) {
            d.removeObject(forKey: "atlas.vault.atrest.\(name)")
        }
        d.removeObject(forKey: Self.restoreIdentityKey)
        d.removeObject(forKey: Self.restoreUsernamesKey)
        d.removeObject(forKey: Self.restoreCurrentKey)
    }

    private func vaultBlobKey(for persona: Profile?) -> String {
        "atlas.vault.atrest.\(persona?.username ?? "__identity__")"
    }

    /// Persist the current persona's vault AT REST (sealed key + ciphertexts only).
    private func saveVaultAtRest() {
        guard let v = vault as? SecureVaultStore else { return }
        UserDefaults.standard.set(v.atRestExport(), forKey: vaultBlobKey(for: currentPersona))
    }

    /// Relaunch path: Face ID (enclave release) -> rebuild identity + personas + vault -> live.
    func restoreSession() {
        guard !enrolled, let sealed = UserDefaults.standard.data(forKey: Self.restoreIdentityKey) else { return }
        guard let state = enclave.release(sealed, liveSample: biometric, label: Self.restoreSealLabel),
              let tree = try? IdentityTree.restore(from: state, sphincs: sphincs) else {
            add("restore failed — Face ID declined or state unreadable"); return
        }
        self.identity = tree
        let names = UserDefaults.standard.stringArray(forKey: Self.restoreUsernamesKey) ?? []
        self.personas = names.compactMap { try? tree.profile($0, tier: .anonymous) }
        let cur = UserDefaults.standard.string(forKey: Self.restoreCurrentKey) ?? ""
        self.currentPersona = personas.first(where: { $0.username == cur }) ?? personas.first
        if let cp = currentPersona { self.username = cp.username }
        let author = tree.child(.authorship)
        self.device = Device(name: "iPhone", identity: tree, devKey: Primitives.randomBytes(32),
                             bootstrapTunnelKey: Primitives.randomBytes(32), enclave: enclave)
        // 1-phone epoch machinery — same stand-ins as enrol (public beacon; secret epoch key stub).
        let eb = LocalBeacon().round(at: 0)
        self.epochBeacon = eb
        self.drandRound = eb.drandRound()
        let epochKey = Primitives.randomBytes(32)
        self.epochKeyValue = epochKey
        self.wrappedEpochKey = try? device!.wrapEpochKey(epochKey, drandRound: drandRound)
        self.epochLK = Primitives.randomBytes(32)
        if let lk = epochLK, let w = wrappedEpochKey,
           let wl = try? Presence.wrapLK(lk, epochKey: epochKey, drandRound: drandRound) {
            self.epoch = (w, wl)
        }
        // The user just proved presence (Face ID on the enclave release).
        for _ in 0..<20 { livenessGate.update(pSGivenLive: 0.97, pSGivenNotLive: 0.05) }
        openVault(for: currentPersona, fallback: author)
        loadGraph(for: currentPersona)
        openLand(for: currentPersona)
        enrolled = true
        // #42: a real unlock is presence-CAPABLE (ceiling .max); effectiveTier holds .max only while
        // the ratchet's PoLE ticks keep landing, and decays to .standard when presence stalls.
        // (The finer Face-ID→basic / +passcode→standard gradation is a device-session refinement.)
        PresenceUnlock.onUnlock(&presenceUnlock, tier: .max); refreshEffectiveTier()
        add("session restored — welcome back")
        startRatchet()
        connectGroup()          // register on the relay so messaging works after a Face ID unlock
        sendPushRegistration()  // re-bind push token to this persona's mailbox
    }

    func disenrol() {
        PresenceUnlock.onLock(&presenceUnlock); refreshEffectiveTier()   // #42: back to LOCKED
        clearPersistedSession()
        stopRatchet(); group?.stop(); group = nil
        identity = nil; device = nil; enrolmentSecret = nil; epoch = nil
        epochLK = nil; epochKeyValue = nil; sessionKey = nil; epochBeacon = nil; panicVault = nil; coreSessionEstablished = false
        vault = nil; media = nil; enrolled = false; peerLive = false
        recUserPart = nil; recServerShares = []; recoveryPasswordHash = nil; recoveryArmed = false
        ratchetTicks = 0; presenceLive = false; messages = []; historyByPersona = [:]; roster = []; vaultFiles = []; vaultFilesByPersona = [:]; safetyNumber = ""
        currentPersona = nil; personas = []; land = nil; hostedItems = []; votes = []; claimedName = nil
        vaultFilesByPersona = [:]; votesByPersona = [:]; claimedNameByPersona = [:]; defaultCaptureFolderByPersona = [:]; defaultCaptureFolderID = nil
        defaultCaptureByType = [:]; defaultCaptureByTypeByPersona = [:]
        spaceRoots = [:]; verifiedProfiles = []
        presence = nil; presenceLocked = false
        add("Disenrolled — session cleared.")
    }

    /// Render an opaque mailbox handle for the UI: a short prefix only. The node sees the FULL
    /// opaque handle; humans confirm they're talking to the right peer via the safety number
    /// (which is over identity-signed keys), never by reading this token.
    static func shortID(_ id: String) -> String {
        id.count > 10 ? String(id.prefix(8)) + "…" : id
    }

    // MARK: - group bring-up (the system starts when >= 2 users are online)

    /// After enrolment, come online at the node and co-derive the shared group LK
    /// with everyone present. The session goes LIVE (ratchet runs) only once at least
    /// one other member is online and the LK is co-derived; a lone user waits.
    func connectGroup() {
        guard !nodeURL.isEmpty else { add("no node configured — set your node URL in Settings ▸ Node"); return }
        guard let author = authorship, let url = URL(string: nodeURL) else { add("bad node URL"); return }
        // OPAQUE MAILBOX HANDLE (privacy): the relay must NEVER see a human name — and NOT the root
        // systemIDHandle either (that's the cross-partition master id verification + device enrolment
        // key on). Register under a STABLE, per-context MESSAGING SLICE (the "messaging" pseudonym):
        // opaque, stable, unlinkable to the root or to other slices; only the System-ID holder can
        // prove linkage. `username` stays LOCAL (display only); name+password is in-person recovery
        // ONLY. (Full disclosure-tier / persona resolution is the follow-on — PLATFORM_PLAN §1.)
        guard let idTree = identity else { add("no identity — enrol first"); return }
        // Messaging identity is the CURRENT PERSONA's messaging slice — so each persona relays
        // under its own opaque mailbox (isolated per persona). Falls back to the identity-level
        // messaging pseudonym if somehow no persona is active.
        let msgSlice = (try? currentPersona?.feature("messaging"))?.handle
            ?? (try? idTree.pseudonym("messaging", tier: .anonymous))?.handle
            ?? idTree.systemIDHandle()
        let me = msgSlice.map { String(format: "%02x", $0) }.joined()
        let g = GroupRelay(baseURL: url, me: me, authorship: author, drandRound: drandRound)
        group = g
        nodeConnected = false                              // not "online" until the relay answers
        g.onRoster = { [weak self] r in
            guard let self else { return }
            self.nodeConnected = true                      // the relay actually responded
            self.serverReachable = true                    // relay answered => server is online (green)
            self.roster = r
            let peers = r.map { Self.shortID($0) }.joined(separator: ", ")
            self.add("roster: you=\(self.username) [\(Self.shortID(me))] · peers: \(peers.isEmpty ? "—" : peers)")
        }
        g.onLK = { [weak self] lk in
            guard let self else { return }
            if let lk {
                self.bindLiveLK(lk)                        // epoch key wraps the LIVE group LK
                if !self.peerLive {
                    self.peerLive = true
                    self.add("Live group session ✓ — \(self.roster.count + 1) online.")
                    self.startRatchet()                    // the session goes live ONLY now
                }
            } else if self.peerLive {
                self.peerLive = false                      // everyone left -> fail closed
            }
        }
        g.onMessage = { [weak self] frm, raw in
            guard let self else { return }
            DispatchQueue.main.async {
                // Unwrap the sealed payload: display name + agent-flag travel inside it (the relay
                // saw only ciphertext). Fall back to the opaque short id for legacy/plain messages.
                var name = Self.shortID(frm), body = raw, isAgent = false
                if let d = raw.data(using: .utf8),
                   let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any],
                   let t = o["t"] as? String {
                    name = (o["n"] as? String) ?? name
                    body = t
                    isAgent = (o["a"] as? Bool) ?? false
                }
                self.appendMessage("\(name): \(body)")
                // Surface to the chat UI — a message from another human, or an AI answer relayed
                // from the peer's device. MessagingView mirrors these into the open chat.
                self.relayMessages.append(ChatMessage(sender: name, text: body, isAgent: isAgent))
            }
        }
        g.onStatus = { [weak self] s in self?.nodeConnected = true; self?.serverReachable = true; self?.add(s) }
        g.onSafetyNumber = { [weak self] s in self?.safetyNumber = s; self?.add("safety number: \(s) — compare with the others to rule out a MITM") }
        g.start()
        add("online as \(username) — waiting for others to come online…")
    }

    /// Tear down the current group session and rejoin the node fresh (e.g. after
    /// changing the node URL, or to recover from a stalled handshake).
    func reconnectGroup() {
        group?.stop(); group = nil; nodeConnected = false
        peerLive = false; roster = []; safetyNumber = ""
        add("reconnecting to \(nodeURL)…")
        connectGroup()
    }

    /// TRUE only once the relay node has ACTUALLY responded (roster/status received) — not
    /// merely that a client object exists. This is the honest "Node online" signal.
    @Published private(set) var nodeConnected = false
    /// Whether a relay client exists / is attempting to reach the node.
    var groupOnline: Bool { group != nil }

    /// Bind the co-derived live LK: wrap it under the presence-gated epoch key so
    /// the epoch key wraps the REAL two-phone LK (not a stub). The LK stays private.
    private func bindLiveLK(_ lk: Data) {
        guard let ek = epochKeyValue, let wek = wrappedEpochKey else { return }
        epochLK = lk
        if let wrappedLK = try? Presence.wrapLK(lk, epochKey: ek, drandRound: drandRound) {
            epoch = (wek, wrappedLK)
            add("epoch key now wraps the live co-derived LK (presence-released).")
        }
    }

    /// Broadcast a message to the group over the live session (LK stays private). The sender's
    /// DISPLAY NAME + agent-flag ride INSIDE the sealed payload — the relay only ever sees an
    /// opaque sealed blob, but the recipient shows the real name ("Alice", not a hex id) and can
    /// render AI replies distinctly. `as name` defaults to your username; pass an agent label +
    /// isAgent:true to relay an AI answer to peers.
    func send(_ text: String, as name: String? = nil, isAgent: Bool = false) {
        guard let g = group, peerLive, !text.isEmpty else { return }
        let display = name ?? (username.isEmpty ? "friend" : username)
        let payload: [String: Any] = ["n": display, "t": text, "a": isAgent]
        let wire = (try? JSONSerialization.data(withJSONObject: payload))
            .flatMap { String(data: $0, encoding: .utf8) } ?? text
        appendMessage("me: \(text)")
        g.send(wire)
    }

    // MARK: - duress

    /// Unlock under a code: the normal password opens the REAL vault; the panic code
    /// opens a DECOY (identical surface — an observer can't tell). The `duress` flag
    /// is internal-only and never surfaced.
    func unlockUnderCode(_ code: String) -> UnlockResult? { panicVault?.unlock(Data(code.utf8)) }

    // MARK: - duress code gate + response (Axiom 5: coercion resistance)
    //
    // Face ID proves WHO is present; the unlock code proves FREE WILL. A coercer who Face-IDs
    // the owner in still can't tell a normal code from a panic code. On a panic code the app
    // LOCKS, captures + SEALS + STREAMS sensor evidence off-device (the node holds ciphertext it
    // can't read — survives a wipe), then applies the owner's PRE-CHOSEN response:
    //   • decoy  — open a dummy, empty session (real identity never unsealed)
    //   • wipe   — zeroize the real key (permanent brick) then show the decoy
    //   • silent — open the REAL session normally but flag duress + keep streaming evidence
    enum DuressResponse: String, CaseIterable { case decoy, wipe, silent }
    enum UnlockCodeResult { case normal, duress, invalid }

    private static let duressRequireKey = "atlas.duress.requireCode"
    private static let duressResponseKey = "atlas.duress.response"
    private static let duressSaltKey = "atlas.duress.salt"
    private static let duressNormalKey = "atlas.duress.normalH"
    private static let duressPanicKey = "atlas.duress.panicH"
    private static let duressPhraseKey = "atlas.duress.phraseH"
    private static let duressPhrasePlainKey = "atlas.duress.phrasePlain"   // normalized, for fuzzy voice match only
    private static let duressCapKey = "atlas.duress.capBytes"
    private static let duressDecoySeedKey = "atlas.duress.decoySeed.sealed"   // #40: decoy persona seed, sealed under the panic code

    @Published var decoyMode = false          // the live session is a dummy (duress)
    @Published private(set) var duressFlagged = false

    // MARK: - Trusted panic contacts (alert + mutual-consent forensic guardians)

    /// A person you've designated to be told when you set off panic. `guardian == true` also means
    /// they can COLLECT your panic forensics — but only under mutual consent: they hold a Shamir
    /// contact-share from when you designated them, and your matching owner-share is released ONLY
    /// when panic fires. Neither share alone opens anything (see `GuardianForensics`).
    struct PanicContact: Codable, Identifiable, Equatable {
        var id: String { name }
        var name: String            // maps to a direct-chat peer (Comms/Contacts)
        var guardian: Bool = false  // may collect forensics on panic (2-of-2, both must agree)
    }
    @Published var panicContacts: [PanicContact] = [] { didSet { savePanicContacts() } }
    private static let panicContactsKey = "atlas.panic.contacts.v1"
    private static let witnessForensicKeyKey = "atlas.panic.witness.fk"                    // one key, all guardians split it
    private static let guardianOwnerShareKeyPrefix = "atlas.panic.guardian.ownershare."    // + name
    private static let guardianContactShareKeyPrefix = "atlas.panic.guardian.contactshare." // + name

    func loadPanicContacts() {
        if let d = UserDefaults.standard.data(forKey: Self.panicContactsKey),
           let list = try? JSONDecoder().decode([PanicContact].self, from: d) {
            panicContacts = list
        }
    }
    private func savePanicContacts() {
        if let d = try? JSONEncoder().encode(panicContacts) {
            UserDefaults.standard.set(d, forKey: Self.panicContactsKey)
        }
    }

    /// The single witness forensic key. All guardians hold a 2-of-2 split of THIS key, so the witness
    /// stream is sealed once yet each guardian's (contact-share + released owner-share) reconstructs
    /// it independently. Device-local at rest (iOS data protection). HARDENING (documented follow-up):
    /// a shipping build seals this under a NON-biometric Secure-Enclave key so the witness can seal
    /// silently while a coercer holding the decoy surface still can't extract it.
    private func witnessForensicKey() -> Data {
        if let k = UserDefaults.standard.data(forKey: Self.witnessForensicKeyKey), k.count == 32 { return k }
        let k = GuardianForensics.newForensicKey()
        UserDefaults.standard.set(k, forKey: Self.witnessForensicKeyKey)
        return k
    }

    /// Designate a trusted contact for panic. If `guardian`, set up the 2-of-2 forensic split now:
    /// the contact's share is staged for delivery (their standing consent), the owner's share is
    /// stored locally and released only on panic. Re-adding a name updates the guardian flag.
    func addPanicContact(_ name: String, guardian: Bool) {
        let n = name.trimmingCharacters(in: .whitespaces)
        guard !n.isEmpty else { return }
        if let i = panicContacts.firstIndex(where: { $0.name == n }) {
            panicContacts[i].guardian = guardian
        } else {
            panicContacts.append(PanicContact(name: n, guardian: guardian))
        }
        if guardian { ensureGuardianSplit(for: n) }
        else { clearGuardianSplit(for: n) }
        add("panic contact \(guardian ? "(guardian) " : "")added — \(n)")
    }

    func removePanicContact(_ name: String) {
        panicContacts.removeAll { $0.name == name }
        clearGuardianSplit(for: name)
    }

    /// Create the standing 2-of-2 for a guardian if absent. The owner-share stays local (released on
    /// panic); the contact-share is staged for delivery when they accept — in this PoC it's sent on
    /// the alert channel. Both split the shared `witnessForensicKey`.
    private func ensureGuardianSplit(for name: String) {
        guard UserDefaults.standard.data(forKey: Self.guardianOwnerShareKeyPrefix + name) == nil,
              let grant = try? GuardianForensics.setupGuardian(forensicKey: witnessForensicKey()) else { return }
        UserDefaults.standard.set(grant.ownerShare.encode(), forKey: Self.guardianOwnerShareKeyPrefix + name)
        UserDefaults.standard.set(grant.contactShare.encode(), forKey: Self.guardianContactShareKeyPrefix + name)
    }
    private func clearGuardianSplit(for name: String) {
        UserDefaults.standard.removeObject(forKey: Self.guardianOwnerShareKeyPrefix + name)
        UserDefaults.standard.removeObject(forKey: Self.guardianContactShareKeyPrefix + name)
    }

    private var guardianContacts: [PanicContact] { panicContacts.filter { $0.guardian } }

    // Continuous WITNESS state (the black-box recorder). Runs until the user-defined vault budget
    // is exhausted or the phone powers off.
    @Published private(set) var witnessActive = false
    @Published private(set) var witnessBytes = 0
    @Published private(set) var witnessFrames = 0
    private let witnessLocation = WitnessLocation()
    private let witnessNetwork = WitnessNetwork()
    private var witnessTask: Task<Void, Never>?
    private var witnessFileURL: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("atlas-witness.log")
    }

    /// User-defined vault budget for the witness recorder (bytes). Default 200 MB.
    var witnessCapBytes: Int {
        get { let v = UserDefaults.standard.integer(forKey: Self.duressCapKey); return v > 0 ? v : 200 * 1024 * 1024 }
        set { UserDefaults.standard.set(newValue, forKey: Self.duressCapKey) }
    }

    /// The password login is REQUIRED on every unlock — Face ID proves WHO, the password proves
    /// FREE WILL and carries the duress channel. Always on once codes are set (part of the design).
    var duressRequireCode: Bool {
        get { (UserDefaults.standard.object(forKey: Self.duressRequireKey) as? Bool) ?? true }
        set { UserDefaults.standard.set(newValue, forKey: Self.duressRequireKey) }
    }
    var duressResponse: DuressResponse {
        get { DuressResponse(rawValue: UserDefaults.standard.string(forKey: Self.duressResponseKey) ?? "") ?? .decoy }
        set { UserDefaults.standard.set(newValue.rawValue, forKey: Self.duressResponseKey) }
    }
    /// Are unlock codes configured on this device? (Set at enrol; older sessions may lack them.)
    var duressConfigured: Bool { UserDefaults.standard.data(forKey: Self.duressNormalKey) != nil }

    private func codeHash(_ code: String, salt: Data) -> Data {
        // PoC verifier: salted hash so UnlockView can branch BEFORE unsealing the real session.
        // (A shipping build uses a slow KDF like PanicVault's scrypt; noted honestly.)
        Primitives.H(Data("atlas/duress-code".utf8), salt, Data(code.utf8))
    }

    /// Record the normal + panic codes at enrol (verifiers only — the codes themselves are never
    /// stored). Defaults the response to decoy + require-code ON if unset.
    /// Arm password + panic code. `decoy` is the SELF-SELECTED persona to present under duress — a
    /// persona you actually use, so it has real history and is plausible to a coercer. If nil, a
    /// synthetic fallback persona is sealed instead (empty, but always present).
    func configureDuress(normalCode: String, panicCode: String, decoy: Profile? = nil) {
        guard !normalCode.isEmpty, !panicCode.isEmpty else { return }
        let salt = Primitives.randomBytes(16)
        UserDefaults.standard.set(salt, forKey: Self.duressSaltKey)
        UserDefaults.standard.set(codeHash(normalCode, salt: salt), forKey: Self.duressNormalKey)
        UserDefaults.standard.set(codeHash(panicCode, salt: salt), forKey: Self.duressPanicKey)
        duressRequireCode = true    // password login is always required (design)
        if UserDefaults.standard.string(forKey: Self.duressResponseKey) == nil { duressResponse = .decoy }
        sealDuressDecoy(panicCode: panicCode, salt: salt, decoy: decoy)
        add("password + panic code armed — password required on every unlock")
    }

    /// Choose (or change) which persona is presented under duress, after duress is already armed.
    /// Requires the panic code to re-seal under it.
    func setDuressDecoy(_ persona: Profile, panicCode: String) {
        guard let salt = UserDefaults.standard.data(forKey: Self.duressSaltKey),
              codeHash(panicCode, salt: salt) == UserDefaults.standard.data(forKey: Self.duressPanicKey) else {
            add("decoy not set — panic code did not match"); return
        }
        sealDuressDecoy(panicCode: panicCode, salt: salt, decoy: persona)
        add("duress decoy set to persona “\(persona.username)”")
    }

    /// Seal the decoy persona (a SELF-SELECTED real persona if given — plausible because it has
    /// real history — else a synthetic fallback) under the panic code, so a duress unlock rebuilds
    /// exactly that persona WITHOUT reassembling the root. Stores seed(32)||name as ONE opaque blob,
    /// so nothing on disk names which persona is the decoy.
    private func sealDuressDecoy(panicCode: String, salt: Data, decoy: Profile?) {
        guard let tree = identity else { return }
        let seed = decoy.map { tree.profileSeed($0.username, tier: $0.tier) } ?? tree.duressPersonaSeed(0)
        let name = decoy?.username ?? "me"
        let key = Primitives.H(Data("atlas/duress-decoy-seal".utf8), codeHash(panicCode, salt: salt))
        if let sealed = try? Primitives.aeadEncrypt(key: key, plaintext: seed + Data(name.utf8)) {
            UserDefaults.standard.set(sealed, forKey: Self.duressDecoySeedKey)
        }
    }

    /// Set (or clear) a PANIC PHRASE — a phrase you can type/say anywhere (chat box, AI prompt)
    /// that silently fires the same duress witness as the panic code, without unlocking anything.
    func setPanicPhrase(_ phrase: String) {
        let salt = UserDefaults.standard.data(forKey: Self.duressSaltKey) ?? Primitives.randomBytes(16)
        UserDefaults.standard.set(salt, forKey: Self.duressSaltKey)
        let p = phrase.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if p.isEmpty {
            UserDefaults.standard.removeObject(forKey: Self.duressPhraseKey)
            UserDefaults.standard.removeObject(forKey: Self.duressPhrasePlainKey)
        } else {
            UserDefaults.standard.set(codeHash(p, salt: salt), forKey: Self.duressPhraseKey)   // exact (typed)
            // Normalized plaintext, ONLY for fuzzy VOICE matching (speech transcripts vary in
            // punctuation/number-spelling). The phrase is low-sensitivity — knowing it lets no one
            // harm you, it only fires YOUR witness — so plaintext-for-voice is an acceptable tradeoff.
            UserDefaults.standard.set(Self.normalizeForVoice(p), forKey: Self.duressPhrasePlainKey)
        }
    }
    var hasPanicPhrase: Bool { UserDefaults.standard.data(forKey: Self.duressPhraseKey) != nil }

    /// Opt-in continuous on-device listening for the spoken panic phrase (default OFF). When on, the
    /// mic runs and the iOS mic indicator shows — a tell + battery cost — so the user chooses it.
    @Published var voicePanicEnabled = UserDefaults.standard.bool(forKey: "atlas.voicepanic.enabled") {
        didSet { UserDefaults.standard.set(voicePanicEnabled, forKey: "atlas.voicepanic.enabled"); syncVoicePanic() }
    }
    private lazy var panicListener = PanicListener(session: self)

    /// Start/stop the on-device spoken-panic-phrase listener to match the toggle + enrolment state.
    /// Call on toggle change, on going live/restoring, and when the app becomes active.
    func syncVoicePanic() {
        if voicePanicEnabled, enrolled, hasPanicPhrase { panicListener.start() } else { panicListener.stop() }
    }

    /// Consume a pending panic set by the Siri App Intent (which only left a flag + opened the app).
    /// Fires the witness if the flag is fresh. Call when the app becomes active.
    func firePendingPanicIfAny() {
        let k = AtlasPanicIntent.pendingKey
        let t = UserDefaults.standard.double(forKey: k)
        guard t > 0, Date().timeIntervalSince1970 - t < 120 else {
            if t > 0 { UserDefaults.standard.removeObject(forKey: k) }; return
        }
        UserDefaults.standard.removeObject(forKey: k)
        Task { @MainActor in await triggerDuress(silentInPlace: true, trigger: "siri-panic") }
    }

    static func normalizeForVoice(_ s: String) -> String {
        let lowered = s.lowercased()
        let mapped = lowered.unicodeScalars.map {
            CharacterSet.alphanumerics.contains($0) ? Character($0) : " "
        }
        return String(mapped).split(separator: " ").joined(separator: " ")
    }

    /// Fuzzy VOICE match: does an on-device transcript contain the panic phrase (normalized)?
    func voiceMatchesPanicPhrase(_ transcript: String) -> Bool {
        guard let want = UserDefaults.standard.string(forKey: Self.duressPhrasePlainKey), !want.isEmpty
        else { return false }
        return Self.normalizeForVoice(transcript).contains(want)
    }

    /// Pure matcher — does this text equal the set panic phrase? No side effects, so callers choose
    /// the response (silent mid-session fire vs a decoy unlock at the lock screen).
    func matchesPanicPhrase(_ text: String) -> Bool {
        guard let salt = UserDefaults.standard.data(forKey: Self.duressSaltKey),
              let want = UserDefaults.standard.data(forKey: Self.duressPhraseKey) else { return false }
        let p = text.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return !p.isEmpty && codeHash(p, salt: salt) == want
    }

    /// Check arbitrary typed/spoken text for the panic phrase — call from ANY text entry point
    /// (messaging, AI prompt, search, compose). If it matches, fire the witness SILENTLY (no UI
    /// change, keep the surface) and swallow the text. Use at the lock screen via `matchesPanicPhrase`
    /// + `triggerDuress(code:)` instead, so the phrase there produces a full decoy unlock.
    @discardableResult
    func checkPanicPhrase(_ text: String) -> Bool {
        guard matchesPanicPhrase(text) else { return false }
        Task { @MainActor in await triggerDuress(silentInPlace: true) }   // no UI change — keep the surface
        return true
    }

    /// FUTURE HOOK: a danger-sensing wearable (abnormal vitals / distress) escalates to the same
    /// forensic witness. The wearable/presence layer will call this when such devices exist; today
    /// it's the documented entry point, not an active detector.
    func wearableDuressDetected(reason: String = "wearable-danger") {
        Task { @MainActor in await triggerDuress(silentInPlace: true, trigger: reason) }
    }

    func evaluateUnlockCode(_ code: String) -> UnlockCodeResult {
        guard let salt = UserDefaults.standard.data(forKey: Self.duressSaltKey),
              let normal = UserDefaults.standard.data(forKey: Self.duressNormalKey),
              let panic = UserDefaults.standard.data(forKey: Self.duressPanicKey) else { return .normal }
        let h = codeHash(code, salt: salt)
        if h == normal { return .normal }
        if h == panic { return .duress }
        return .invalid
    }

    /// The panic path: start the continuous WITNESS, then apply the pre-chosen response. Never
    /// reveals to a watcher that anything unusual happened. `silentInPlace` = don't touch the
    /// current surface (used by the panic phrase / wearable escalation mid-session).
    @MainActor
    func triggerDuress(silentInPlace: Bool = false, trigger: String = "duress-unlock", code: String? = nil) async {
        duressFlagged = true
        startDuressWitness(trigger: trigger)       // continuous — runs until vault full or power off
        await firePanicAlerts(trigger: trigger)    // tell trusted contacts + release guardian shares
        if silentInPlace { return }                // phrase/wearable: keep the current surface as-is
        switch duressResponse {
        case .wipe:
            panicVault?.zeroizeOnSuspicion("duress code entered")
            enterDecoyMode(code: code)             // after the brick, show the decoy persona (no error tell)
        case .decoy:
            enterDecoyMode(code: code)
        case .silent:
            restoreSession()                       // REAL session — but flagged + still witnessing
        }
    }

    // MARK: continuous witness recorder

    /// Begin the black-box witness: a full sensor + location + network frame every ~second, sealed,
    /// appended to the local vault file (primary) AND streamed off-device to the user's node
    /// (durable — survives the phone). Runs until the user-defined budget is spent or power off.
    @MainActor
    func startDuressWitness(trigger: String) {
        guard !witnessActive else { return }
        witnessActive = true; witnessBytes = 0; witnessFrames = 0
        witnessLocation.requestAuthorization(); witnessLocation.start(); witnessNetwork.start()
        add("⚠️ WITNESS started (\(trigger)) — streaming to vault + your node until \(witnessCapBytes / (1024*1024)) MB or power off")
        witnessTask = Task { [weak self] in
            while let self, self.witnessActive, self.witnessBytes < self.witnessCapBytes {
                await self.captureWitnessFrame(trigger: trigger)
                try? await Task.sleep(nanoseconds: 1_000_000_000)   // ~1 Hz continuous
            }
            await self?.stopDuressWitness(reason: "budget/stop")
        }
    }

    @MainActor
    func stopDuressWitness(reason: String = "stopped") {
        guard witnessActive else { return }
        witnessActive = false
        witnessTask?.cancel(); witnessTask = nil
        witnessLocation.stop(); witnessNetwork.stop()
        add("witness ended (\(reason)) — \(witnessFrames) frames, \(witnessBytes / 1024) KB")
    }

    /// One witness frame: maximal sensors + location + network + device state → sealed → vault
    /// (local append) + node (off-device). Everything is sealed under the device enclave, so the
    /// witness keeps recording even in WIPE mode after the identity key is destroyed.
    @MainActor
    private func captureWitnessFrame(trigger: String) async {
        var window = Data()
        for _ in 0..<4 { await ambient.refreshSnapshot(); window.append(ambient.fusedWindow()) }
        var battery: Float = -1
        #if canImport(UIKit)
        UIDevice.current.isBatteryMonitoringEnabled = true
        battery = UIDevice.current.batteryLevel
        #endif
        let frame: [String: Any] = [
            "v": 1, "trigger": trigger, "seq": witnessFrames,
            "ts": Date().timeIntervalSince1970, "battery": battery,
            "location": witnessLocation.snapshot(), "network": witnessNetwork.snapshot(),
            "persona": currentPersona?.username ?? "—",
        ]
        let meta = (try? JSONSerialization.data(withJSONObject: frame)) ?? Data()
        let plain = meta + Data([0x00]) + window
        let sealed = enclave.seal(plain, label: Data("atlas/witness".utf8))
        // PRIMARY: append to the local vault file (always works; survives app restart).
        appendWitnessLocal(sealed)
        witnessFrames += 1
        witnessBytes += sealed.count
        // GUARDIAN copy: if any trusted contact is a forensic guardian, seal the SAME frame under the
        // shared witness forensic key too and stream it to the node. A guardian collects it only via
        // the 2-of-2 (their contact-share + the owner-share released on panic) — see GuardianForensics.
        if !guardianContacts.isEmpty,
           let gsealed = try? GuardianForensics.sealForensic(forensicKey: witnessForensicKey(), data: plain) {
            await postDurable(blob: gsealed, meta: "guardian-witness:\(trigger)")
        }
        // DURABLE off-device: stream to the user's node (relay forwards; node holds ciphertext it
        // can't read). Best-effort, silent on failure — never a tell to a coercer.
        await postDurable(blob: sealed, meta: "witness:\(trigger)")
    }

    /// Best-effort durable POST of a sealed blob to the node's `/duress` sink (ciphertext the node
    /// can't read). Silent on failure — never a tell to a coercer.
    private func postDurable(blob: Data, meta: String) async {
        guard let url = URL(string: nodeURL + "/duress") else { return }
        var req = URLRequest(url: url); req.httpMethod = "POST"; req.timeoutInterval = 8
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try? JSONSerialization.data(withJSONObject: ["blob": blob.base64EncodedString(),
                                                                    "meta": meta])
        _ = try? await URLSession.shared.data(for: req)
    }

    /// On panic: tell every trusted contact WHERE you are and WHEN, and release each guardian's
    /// owner-share so they can collect your forensics (they already hold their contact-share — the
    /// 2-of-2 only completes now, on your release: "both parties agree"). Best-effort + silent, so a
    /// coercer watching the screen sees nothing. Cross-device pickup is a durable node post the
    /// contact's app fetches (the contact-side inbox fetch is the remaining device-side slice).
    @MainActor
    func firePanicAlerts(trigger: String) async {
        guard !panicContacts.isEmpty else { return }
        let loc = witnessLocation.snapshot()
        let ts = Date().timeIntervalSince1970
        let who = currentPersona?.username ?? username
        for c in panicContacts {
            let alert: [String: Any] = ["type": "panic", "from": who, "ts": ts,
                                        "trigger": trigger, "location": loc]
            if let data = try? JSONSerialization.data(withJSONObject: alert) {
                await postDurable(blob: data, meta: "panic-alert:\(c.name)")
            }
            // Guardian: release the owner-share + (re)stage the contact-share, so this contact can
            // reconstruct the witness forensic key and collect. Neither share alone opens anything.
            if c.guardian,
               let owner = UserDefaults.standard.data(forKey: Self.guardianOwnerShareKeyPrefix + c.name),
               let contact = UserDefaults.standard.data(forKey: Self.guardianContactShareKeyPrefix + c.name),
               let release = try? JSONSerialization.data(withJSONObject: [
                    "type": "guardian-release", "from": who, "ts": ts,
                    "owner_share": owner.base64EncodedString(),
                    "contact_share": contact.base64EncodedString()]) {
                await postDurable(blob: release, meta: "guardian-release:\(c.name)")
            }
        }
        let g = guardianContacts.count
        add("panic alerts sent to \(panicContacts.count) contact(s)" + (g == 0 ? "" : ", \(g) guardian release(s)"))
    }

    /// CONTACT SIDE — collect a guardian's forensic capture. Reconstructs the witness forensic key
    /// from the two shares (yours, held since you accepted, + theirs, released on their panic) and
    /// opens a sealed guardian-witness frame. Returns nil unless BOTH shares are present and valid —
    /// mutual consent enforced by the 2-of-2, not by policy. The `sealedFrame` is one blob the node
    /// held (meta `guardian-witness:*`). The inbox fetch that pulls the release + frames from the node
    /// is the remaining device-side slice.
    func collectGuardianForensic(ownerShareB64: String, contactShareB64: String, sealedFrame: Data) -> Data? {
        guard let od = Data(base64Encoded: ownerShareB64), let cd = Data(base64Encoded: contactShareB64) else { return nil }
        let owner = Shamir.Share.decode(od), contact = Shamir.Share.decode(cd)
        guard let fk = try? GuardianForensics.collectForensicKey(contactShare: contact, ownerShare: owner),
              let plain = try? GuardianForensics.openForensic(forensicKey: fk, blob: sealedFrame) else { return nil }
        return plain
    }

    private func appendWitnessLocal(_ sealed: Data) {
        var rec = withUnsafeBytes(of: UInt32(sealed.count).bigEndian) { Data($0) }
        rec.append(sealed)
        let url = witnessFileURL
        if let fh = try? FileHandle(forWritingTo: url) {
            defer { try? fh.close() }
            _ = try? fh.seekToEnd(); try? fh.write(contentsOf: rec)
        } else {
            try? rec.write(to: url)
        }
    }

    /// A dummy, empty live session — the real identity is never unsealed. Surface looks set up.
    private func enterDecoyMode(code: String? = nil) {
        decoyMode = true
        username = username.isEmpty ? "me" : username
        var decoy: Profile?
        var fallback: Child?
        // #40: rebuild the DETERMINISTIC decoy persona from the panic-sealed seed — no real System-ID
        // is reassembled. It presents as a full, plausible persona (its own vault, persistent across
        // duress unlocks) yet is cryptographically unlinkable to the root and to the real personas.
        if let code, let salt = UserDefaults.standard.data(forKey: Self.duressSaltKey),
           let sealed = UserDefaults.standard.data(forKey: Self.duressDecoySeedKey) {
            let key = Primitives.H(Data("atlas/duress-decoy-seal".utf8), codeHash(code, salt: salt))
            if let blob = try? Primitives.aeadDecrypt(key: key, blob: sealed), blob.count > 32 {
                let seed = blob.prefix(32)
                let name = String(decoding: blob.dropFirst(32), as: UTF8.self)   // the decoy's own name
                if let p = try? IdentityTree.personaFromSeed(Data(seed), username: name) {
                    decoy = p
                    username = name                   // present as the decoy persona, not the real login name
                    fallback = try? p.feature("authorship")
                    self.identity = nil               // a decoy session holds NO real tree
                }
            }
        }
        if decoy == nil {
            // fallback: throwaway random-tree persona (duress armed before identity existed / legacy)
            if let seed = try? Optional(Primitives.randomBytes(32)) ?? nil,
               let tree = try? IdentityTree.build(tskSeed: seed, sphincs: sphincs) {
                self.identity = tree
                decoy = try? tree.profile(username, tier: .anonymous)
                fallback = tree.child(.authorship)
            }
        }
        self.currentPersona = decoy
        self.personas = decoy.map { [$0] } ?? []   // real personas are NEVER listed under duress
        if let fb = fallback { openVault(for: currentPersona, fallback: fb) }
        for _ in 0..<20 { livenessGate.update(pSGivenLive: 0.97, pSGivenNotLive: 0.05) }
        enrolled = true
        // #42: a duress unlock is capped at the scoped DURESS tier regardless of presence.
        PresenceUnlock.onUnlock(&presenceUnlock, tier: .max, duress: true); refreshEffectiveTier()
        add("⚠️ decoy session (duress) — real identity sealed + untouched; evidence streamed off-device")
    }


    /// Zeroize-on-suspicion: destroy the real key (permanent brick) and clear the
    /// session. The decoy survives; the real secrets are unrecoverable.
    func panicWipe(_ reason: String = "user-initiated panic wipe") {
        panicVault?.zeroizeOnSuspicion(reason)
        add("⚠️ zeroize-on-suspicion fired — real key destroyed; real vault is a permanent brick.")
        disenrol()
    }

    // MARK: - distributed recovery (userHalf 2-of-3 + serverHalf k-of-N)

    private func armRecovery(seed: Data, password: String) {
        let userPart = Primitives.randomBytes(seed.count)
        let serverPart = Data(zip(seed, userPart).map { $0 ^ $1 })     // seed = userPart XOR serverPart
        recUserPart = userPart                                         // held WHOLE on USB + wallet (either suffices)
        recServerShares = Shamir.split(serverPart, n: 3, k: 2)         // serverPart split k-of-N across the nodes
        recoveryPasswordHash = Primitives.H(Data("atlas/recovery-pw".utf8), Data(password.utf8))
        recoveryArmed = true
        add("recovery armed: userHalf = your possession (USB or wallet) · serverHalf = k-of-N nodes, released only by the in-person server ceremony.")
    }

    /// The USB recovery factor — the WHOLE userPart, written to your drive. It is only
    /// half the seed, so a lost drive recovers nothing without the server ceremony. Your
    /// wallet (phone) holds the same value; either one is enough for the user half.
    func recoveryUSBShare() -> Data? { recUserPart }

    /// Total-loss recovery at a recovery SERVER. The user half comes from possession
    /// (your USB OR your wallet). The server half is released ONLY when the full in-person
    /// ceremony is met: you physically appear at the server, a human verifies your live
    /// presence, your Face ID makes a server-side signature, AND your password matches your
    /// recovery record. Missing any one → the server share stays locked. Returns the
    /// recovered authorship handle (matches the original), or nil if a factor is missing.
    func recoverIdentity(usbData: Data?, walletPresent: Bool,
                         atServer: Bool, humanVerified: Bool,
                         faceIDSignature: Bool, password: String) -> String? {
        guard recoveryArmed, let userPart = recUserPart, recServerShares.count == 3 else { add("recovery not armed"); return nil }

        // USER HALF — possession. Your USB (must match) OR your wallet; either is enough.
        let usbOK = usbData.map { $0 == userPart } ?? false
        guard usbOK || walletPresent else {
            add("recovery BLOCKED: present your USB share or your wallet (phone) — the user half is your possession."); return nil
        }

        // SERVER HALF — the in-person server ceremony, ALL required:
        guard atServer else {
            add("recovery BLOCKED: you must physically appear at a recovery server."); return nil }
        guard humanVerified else {
            add("recovery BLOCKED: a human at the server must verify your live presence."); return nil }
        guard faceIDSignature else {
            add("recovery BLOCKED: the server needs your Face ID signature (verified presence)."); return nil }
        guard let pwh = recoveryPasswordHash,
              Primitives.H(Data("atlas/recovery-pw".utf8), Data(password.utf8)) == pwh else {
            add("recovery BLOCKED: password does not match your recovery record — the server won't release the serverHalf."); return nil }

        let serverPart = Shamir.combine(Array(recServerShares.prefix(2)))                   // k-of-N nodes release
        let seed = Data(zip(userPart, serverPart).map { $0 ^ $1 })                          // userPart XOR serverPart = tskSeed
        guard let tree = try? IdentityTree.build(tskSeed: seed, sphincs: sphincs) else { add("recovery: rebuild failed"); return nil }
        let h = tree.child(.authorship).handle.prefix(6).map { String(format: "%02x", $0) }.joined()
        add("recovered ✓ — userHalf (\(usbOK ? "USB" : "wallet"), possession) + serverHalf (in-person: physical presence + human verification + Face ID signature + password) → identity \(h)…")
        return h
    }

    // MARK: - the self-advancing continuity ratchet (no buttons)

    /// After enrolment the session RUNS on its own: each tick pulls the live ambient
    /// (or ring) timing, presence-gates, and advances the continuity ratchet — with
    /// no user action. The LK / continuity value never leaves this object; only the
    /// running/tick/presence state is @Published. A frozen/absent signal fails closed.
    func startRatchet() {
        guard ratchetTask == nil, let dev = device else { return }
        running = true
        ratchetTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self, self.enrolled else { break }
                let pole = await self.currentPoLE()
                self.presenceLive = pole.operate

                // PRESENCE LIFECYCLE — only while a ring is actually connected (so a
                // ring-less session is never affected). Ring on -> PRESENT; a drop enters
                // the grace window; beyond it -> HARD LOCKDOWN.
                if !self.ring.connectedName.isEmpty {
                    let now = Date().timeIntervalSince1970
                    if self.presence == nil {
                        self.presence = PresenceSession(bindSecret: Primitives.randomBytes(32),
                                                        atS: now, graceS: Self.presenceGraceS)
                    }
                    if self.ring.pulsePresent { self.presence?.pulse(atS: now) }          // resume/stay live
                    else { self.presence?.disconnect(atS: now); self.presence?.checkTimeout(atS: now) }
                    if self.presence?.state == .locked {
                        self.hardLockLive(reason: self.presence?.lockEvent?.reason ?? "removed")
                        break
                    }
                }

                // Biometric-gated release establishes the core session ONCE (one Face ID at
                // unlock) — NOT every tick. Per-tick advance is the silent app-layer rotation
                // below (RAM + silent SE anchor). Re-establishes after a hard lockdown/disenrol.
                if !self.coreSessionEstablished, let lk = self.epochLK, let ek = self.epochKeyValue {
                    _ = try? dev.advanceEpochPresent(lk: lk, epochKey: ek, drandRound: self.drandRound, pole: pole)
                    self.coreSessionEstablished = true
                }
                // ASYNCHRONOUS device clock: the live signal itself sets WHEN the next
                // session-key tick fires (device.nextRatchetInterval(bioSignal) ->
                // tick.intervalS). Each device runs at its own bio-timed tempo — no
                // shared beat. Presence-gated: no live signal -> no advance (fail-closed).
                var nextInterval = 2.0
                if let tick = try? timedRatchetStep(device: dev, source: self.ambientSource,
                                                    pole: pole, drandRound: self.drandRound,
                                                    beacon: Data("atlas/continuity".utf8)),
                   !tick.gatedOut {
                    self.ratchetTicks += 1
                    // PoLE IS ON A CLOCK: each live tick is a presence sample; automatically mint a
                    // PoLE receipt once per window from the live entropy — the user never signs by hand.
                    self.autoMintPresenceReceipt()
                    // #42: a live PoLE tick refreshes presence; MAX holds only while these keep landing.
                    PresenceUnlock.onPresenceTick(&self.presenceUnlock, nowRound: self.unlockRound())
                    self.refreshEffectiveTier()
                    nextInterval = max(1.0, tick.intervalS)
                    // CHEAP per-tick identity binding: rotate the session key, chained
                    // on prev, folding in the LK + public epoch key + authorship handle.
                    // Just an HKDF (no signature, no growing storage) — so every advance
                    // is id-attested at ~zero battery/space cost. The costly signed
                    // attestation is produced only on demand (message/capture/auth).
                    if let lk = self.epochLK, let ek = self.epochKeyValue, let author = self.authorship {
                        // DEVICE CLOCK: fold a SILENT SE contribution (SE anchor rotates 10±2s)
                        // into the RAM-only session key so it's hardware-bound + unreproducible
                        // off THIS enclave. Zero the previous key's bytes before replacing it.
                        let seBind = self.enclave.hardwareTickContribution(Data("atlas/tick|".utf8) + ek + author.handle)
                        let next = Primitives.hkdf(ikm: (self.sessionKey ?? lk) + seBind,
                                                   info: Data("atlas/session-key|".utf8) + ek + author.handle,
                                                   length: 32)
                        let oldN = self.sessionKey?.count ?? 0
                        if oldN > 0 { self.sessionKey?.resetBytes(in: 0..<oldN) }
                        self.sessionKey = next
                        // OPTION: full PQC attestation signature every tick (measured),
                        // and/or captured into the exportable proof log while recording.
                        if self.attestEveryTick || self.proofRecording || self.proofLogging {
                            let t0 = DispatchTime.now().uptimeNanoseconds
                            let sig = (try? HybridSign.sign(author.keypair, self.sessionKey ?? lk)) ?? Data()
                            let ms = Double(DispatchTime.now().uptimeNanoseconds - t0) / 1e6
                            self.sigCount += 1
                            self.avgSignMs = (self.avgSignMs * Double(self.sigCount - 1) + ms) / Double(self.sigCount)
                            if self.proofRecording || self.proofLogging {
                                self.proofLog.append(["at": Date().timeIntervalSince1970,
                                                      "sig": sig.base64EncodedString()])
                                self.proofTicks = self.proofLog.count
                                if self.proofLogging { self.pruneProofLog() }   // keep only the retention window
                            }
                        }
                    }
                }
                try? await Task.sleep(nanoseconds: UInt64(nextInterval * 1_000_000_000))
            }
            self?.running = false
        }
    }

    func stopRatchet() { ratchetTask?.cancel(); ratchetTask = nil; running = false }

    /// HARD LOCKDOWN on sustained live-presence loss: wipe the LIVE layer (LK, session key,
    /// epoch key) so a snatched phone has no live key material, keep the sealed identity, and
    /// record the reason. Terminal for this session — re-present (wear the ring) to rebuild.
    /// A sealed forensic event would be appended here in the full build.
    private func hardLockLive(reason: String) {
        let skN = sessionKey?.count ?? 0; if skN > 0 { sessionKey?.resetBytes(in: 0..<skN) }   // zero RAM bytes first
        let lkN = epochLK?.count ?? 0; if lkN > 0 { epochLK?.resetBytes(in: 0..<lkN) }
        epochLK = nil; sessionKey = nil; epochKeyValue = nil; coreSessionEstablished = false
        presenceLive = false; presenceLocked = true; running = false
        refreshEffectiveTier()   // #42: presence gone -> MAX decays to STANDARD (identity stays sealed/unlocked)
        ratchetTask?.cancel(); ratchetTask = nil
        (enclave as? SecureEnclaveStore)?.dropPresence()   // re-arm Face ID: re-entry must re-auth
        add("🔒 HARD LOCKDOWN — live presence \(reason). Live keys wiped; sealed identity kept. Wear the ring again to rebuild the session.")
    }

    /// Drop the RAM-only live session key on a fail-closed CONDITION (app backgrounded /
    /// device locked / timeout). Zeroes the session key and stops the ratchet; the sealed
    /// identity + epoch material persist, so returning under presence rebuilds the session.
    func wipeLiveKeys() {
        let n = sessionKey?.count ?? 0; if n > 0 { sessionKey?.resetBytes(in: 0..<n) }
        sessionKey = nil
        stopRatchet()
        (enclave as? SecureEnclaveStore)?.dropPresence()   // re-arm Face ID on background/lock
    }

    // MARK: - the one live-presence gate (used by every feature)

    /// The current live PoLE from the real ambient signal (ring swaps in). Refreshed
    /// on demand and folded into the persistent gate, so sustained live change keeps
    /// features operating and a frozen/absent signal erodes it -> fail-closed.
    func currentPoLE() async -> PoLEState {
        if !ring.connectedName.isEmpty, let s = try? ringSource.sample() {
            // CERTIFIED WEARABLE connected → the upgrade to ALIVE & PRESENT, via the live
            // pulse (strict, fail-closed on removal). The Bayesian gate tracks the pulse.
            let (l, nl) = s.present ? (0.9, 0.1) : (0.1, 0.9)
            livenessGate.update(pSGivenLive: l, pSGivenNotLive: nl)
        } else {
            // AMBIENT MODE (no wearable): ACCOUNT + IDENTITY + HUMAN are proven at enrol
            // (enrolled, app/device-attested, human-proven), so the session OPERATES. Keep the
            // gate at its live state — ambient does NOT claim "alive & present" (that upgrade
            // is the certified wearable). This is what opens the vault + saves captures solo.
            livenessGate.update(pSGivenLive: 0.97, pSGivenNotLive: 0.05)
        }
        return livenessGate.state(sensorDigest: Data("atlas/session".utf8), drandRound: drandRound)
    }

    /// Start capturing an exportable proof: from now until `stopProofBundle`, every
    /// ratchet tick's live id-attestation is signed and logged. Bound to a label
    /// (e.g. the video you're recording).
    func startProof(label: String) {
        proofStartedAt = Date(); proofLabel = label; proofRecording = true
        add("proof recording started for \"\(label)\" — capturing per-tick live attestations")
    }

    /// Stop and package the proof for THIS recording window (the attestations since
    /// `startProof`) — a portable JSON bundle binding the identity + epoch to the
    /// time-stamped chain of live attestations. Verifiable evidence a live,
    /// id-attested human was continuously present while the content was made. Does
    /// NOT clear the rolling log.
    func stopProofBundle() -> Data {
        proofRecording = false
        let since = proofStartedAt.timeIntervalSince1970
        let entries = proofLog.filter { ($0["at"] as? Double ?? 0) >= since }
        add("proof bundle: \(entries.count) attested ticks over \(Int(Date().timeIntervalSince(proofStartedAt)))s — ready to export")
        return proofBundleJSON(kind: "recording", label: proofLabel, entries: entries)
    }

    /// Export the current rolling day-log (bounded to `retentionHours`).
    func exportRollingLog() -> Data {
        add("rolling proof log: \(proofLog.count) attestations over the last \(Int(retentionHours))h")
        return proofBundleJSON(kind: "rolling", label: "last-\(Int(retentionHours))h", entries: proofLog)
    }

    func clearProofLog() { proofLog.removeAll(); proofTicks = 0; add("proof log cleared") }

    private func pruneProofLog() {
        let cutoff = Date().timeIntervalSince1970 - retentionHours * 3600
        proofLog.removeAll { ($0["at"] as? Double ?? 0) < cutoff }
        proofTicks = proofLog.count
    }

    private func proofBundleJSON(kind: String, label: String, entries: [[String: Any]]) -> Data {
        let bundle: [String: Any] = [
            "atlas_proof": 1, "kind": kind, "label": label,
            "identity": authorship?.handle.base64EncodedString() ?? "",
            "drandRound": drandRound.base64EncodedString(),
            "attestedTicks": entries.count, "entries": entries,
        ]
        return (try? JSONSerialization.data(withJSONObject: bundle, options: [.prettyPrinted, .sortedKeys])) ?? Data()
    }

    /// Measure raw PQC attestation-signing cost on THIS device: sign `n` times and
    /// report ms/sig + sigs/sec (so we can reason about the per-tick battery cost).
    func signBenchmark(_ n: Int = 200) {
        guard let author = authorship else { add("enrol first"); return }
        let msg = Data("atlas/bench".utf8)
        let t0 = DispatchTime.now().uptimeNanoseconds
        for _ in 0..<n { _ = try? HybridSign.sign(author.keypair, msg) }
        let ms = Double(DispatchTime.now().uptimeNanoseconds - t0) / 1e6
        add("sign bench: \(n) sigs in \(String(format: "%.0f", ms))ms → \(String(format: "%.2f", ms/Double(n)))ms/sig, \(String(format: "%.0f", Double(n)/(ms/1000)))/s")
    }

    /// The public epoch beacon (drand stand-in) — the same value for every device.
    /// Its `drandRound()` matches the session epoch, so provenance/vault stamps line up.
    func beacon() -> BeaconRound { epochBeacon ?? LocalBeacon().round(at: 0) }
}
