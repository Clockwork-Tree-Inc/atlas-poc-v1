import Foundation
import AtlasCore

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

    // Established at enrolment, then read by every feature:
    private(set) var identity: IdentityTree?
    var authorship: Child? { identity?.child(.authorship) }

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
    private var ratchetTask: Task<Void, Never>?

    // GROUP live session: any number of NAMED users join (2 is the minimum to go
    // live). Members are discovered from the node roster; everyone co-derives ONE
    // shared group LK. A lone user waits at `peerLive == false`.
    @Published var nodeURL = "http://192.168.68.106:8787"   // the Mac blind-relay node
    @Published var username = ""                            // this user's name
    @Published private(set) var roster: [String] = []       // OTHER members currently online
    @Published private(set) var peerLive = false            // group LK co-derived (>= 2 online)
    @Published private(set) var messages: [String] = []
    @Published private(set) var safetyNumber = ""           // OOB fingerprint of verified member identities (MITM check)
    private var group: GroupRelay?

    private(set) var vault: SecureVaultStore?
    private(set) var media: MediaVaultStore?
    let ledger = LedgerStub()

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
    private let livenessGate = LivenessGate()
    private var drandRound = Data(count: 8)
    private var panicVault: PanicVault?     // duress: panic code -> decoy; normal -> real
    private let enclave = ModelEnclave()    // shared biometric enclave (vault + recovery)
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

    init() { AtlasFlags.logHonesty() }

    private func add(_ s: String) { log.append(s) }

    /// Internal passthrough so a view (e.g. a blocked intent gesture) can write to the
    /// shared session log without exposing the underlying store.
    func note(_ s: String) { add(s) }

    // MARK: - the one enrolment ritual

    /// Face ID + password + button + live presence -> build the identity, seal the
    /// enrolment secret, establish the epoch, register the YubiKey, and open the
    /// vault. On success every feature unlocks against THIS identity + presence.
    func provision(password: String, panicCode: String, buttonDoubleClicked: Bool) async throws {
        enrolProgress = ["① live pulse from the ring — wear it…"]
        // Liveness is the RING PULSE (fail-closed): if the ring shows no live pulse
        // right now, the ceremony's presence gate closes and enrol is refused. The
        // wizard's ring step already confirmed a pulse before we get here.
        let ceremony = EnrollmentCeremony(sphincs: sphincs)
        let result = try await ceremony.enrol(signalSource: ringSource,
                                               password: password,
                                               buttonDoubleClicked: buttonDoubleClicked,
                                               forensicWindow: true)
        enrolProgress = ["✓ live ring pulse + Face ID + password + button"]
        self.identity = result.identity
        self.enrolmentSecret = result.enrollmentSecret

        let author = result.identity.child(.authorship)
        self.device = Device(name: "iPhone", identity: result.identity,
                             devKey: Primitives.randomBytes(32),
                             bootstrapTunnelKey: Primitives.randomBytes(32))

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

        enrolProgress.append("✓ identity + secret epoch key (presence-gated) + LK binding")

        // Open the shared vault + media store against the enrolled author.
        let v = SecureVaultStore(biometric: biometric, author: author, backup: .phoneOnly)
        self.vault = v
        self.media = MediaVaultStore(vault: v, authorship: author)
        enrolProgress.append("✓ secure vault opened")

        // Duress slice: the panic code opens a DECOY vault (surface identical to the
        // real one); the normal password opens the real one. Zeroize-on-suspicion
        // destroys the real key (a permanent brick), the decoy survives.
        if !panicCode.isEmpty {
            let pv = try PanicVault(normalCode: Data(password.utf8), panicCode: Data(panicCode.utf8)) { reason in
                print("[ATLAS] zeroize-on-suspicion: \(reason)")
            }
            try pv.seedDecoy("wallet", Data("DECOY: small balance, no keys".utf8))
            self.panicVault = pv
        }

        armRecovery(seed: result.identity.tskSeed, password: password)
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
        add("Live — session online.")
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

    func disenrol() {
        stopRatchet(); group?.stop(); group = nil
        identity = nil; device = nil; enrolmentSecret = nil; epoch = nil
        epochLK = nil; epochKeyValue = nil; sessionKey = nil; epochBeacon = nil; panicVault = nil
        vault = nil; media = nil; enrolled = false; peerLive = false
        recUserPart = nil; recServerShares = []; recoveryPasswordHash = nil; recoveryArmed = false
        ratchetTicks = 0; presenceLive = false; messages = []; roster = []; vaultFiles = []; safetyNumber = ""
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
        guard let author = authorship, let url = URL(string: nodeURL) else { add("bad node URL"); return }
        // OPAQUE MAILBOX HANDLE (privacy): the relay must NEVER see a human name — and NOT the root
        // systemIDHandle either (that's the cross-partition master id verification + device enrolment
        // key on). Register under a STABLE, per-context MESSAGING SLICE (the "messaging" pseudonym):
        // opaque, stable, unlinkable to the root or to other slices; only the System-ID holder can
        // prove linkage. `username` stays LOCAL (display only); name+password is in-person recovery
        // ONLY. (Full disclosure-tier / persona resolution is the follow-on — PLATFORM_PLAN §1.)
        guard let idTree = identity else { add("no identity — enrol first"); return }
        let msgSlice = (try? idTree.pseudonym("messaging", tier: .anonymous))?.handle ?? idTree.systemIDHandle()
        let me = msgSlice.map { String(format: "%02x", $0) }.joined()
        let g = GroupRelay(baseURL: url, me: me, authorship: author, drandRound: drandRound)
        group = g
        g.onRoster = { [weak self] r in
            guard let self else { return }
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
        g.onMessage = { [weak self] frm, text in self?.messages.append("\(Self.shortID(frm)): \(text)") }
        g.onStatus = { [weak self] s in self?.add(s) }
        g.onSafetyNumber = { [weak self] s in self?.safetyNumber = s; self?.add("safety number: \(s) — compare with the others to rule out a MITM") }
        g.start()
        add("online as \(username) — waiting for others to come online…")
    }

    /// Tear down the current group session and rejoin the node fresh (e.g. after
    /// changing the node URL, or to recover from a stalled handshake).
    func reconnectGroup() {
        group?.stop(); group = nil
        peerLive = false; roster = []; safetyNumber = ""
        add("reconnecting to \(nodeURL)…")
        connectGroup()
    }

    /// Whether the group relay is currently up (registered at the node).
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

    /// Broadcast a message to the group over the live session (LK stays private).
    func send(_ text: String) {
        guard let g = group, peerLive, !text.isEmpty else { return }
        messages.append("me: \(text)")
        g.send(text)
    }

    // MARK: - duress

    /// Unlock under a code: the normal password opens the REAL vault; the panic code
    /// opens a DECOY (identical surface — an observer can't tell). The `duress` flag
    /// is internal-only and never surfaced.
    func unlockUnderCode(_ code: String) -> UnlockResult? { panicVault?.unlock(Data(code.utf8)) }

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

                if let lk = self.epochLK, let ek = self.epochKeyValue {
                    _ = try? dev.advanceEpochPresent(lk: lk, epochKey: ek, drandRound: self.drandRound, pole: pole)
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
                    nextInterval = max(1.0, tick.intervalS)
                    // CHEAP per-tick identity binding: rotate the session key, chained
                    // on prev, folding in the LK + public epoch key + authorship handle.
                    // Just an HKDF (no signature, no growing storage) — so every advance
                    // is id-attested at ~zero battery/space cost. The costly signed
                    // attestation is produced only on demand (message/capture/auth).
                    if let lk = self.epochLK, let ek = self.epochKeyValue, let author = self.authorship {
                        self.sessionKey = Primitives.hkdf(ikm: self.sessionKey ?? lk,
                                                          info: Data("atlas/session-key|".utf8) + ek + author.handle,
                                                          length: 32)
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
        epochLK = nil; sessionKey = nil; epochKeyValue = nil
        presenceLive = false; presenceLocked = true; running = false
        ratchetTask?.cancel(); ratchetTask = nil
        add("🔒 HARD LOCKDOWN — live presence \(reason). Live keys wiped; sealed identity kept. Wear the ring again to rebuild the session.")
    }

    // MARK: - the one live-presence gate (used by every feature)

    /// The current live PoLE from the real ambient signal (ring swaps in). Refreshed
    /// on demand and folded into the persistent gate, so sustained live change keeps
    /// features operating and a frozen/absent signal erodes it -> fail-closed.
    func currentPoLE() async -> PoLEState {
        // Presence = live RING pulse (fail-closed). Remove the ring / lose the pulse and
        // the gate closes, the ratchet stops advancing — no phone-motion substitute.
        if let s = try? ringSource.sample() {
            let (l, nl) = s.present ? (0.9, 0.1) : (0.1, 0.9)
            livenessGate.update(pSGivenLive: l, pSGivenNotLive: nl)
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
