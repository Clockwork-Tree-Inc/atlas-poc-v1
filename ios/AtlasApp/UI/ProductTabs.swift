import SwiftUI
import AtlasCore

// The consumer PRODUCT tabs, laid out to match the design notes:
//   ① Home  (profile selector + system-health metrics: Wallet / Wearable / Server)
//   ② Contacts
//   ③ Spaces (the cascading space graph for the active profile)
//   + Market, Email, Camera/Capture, Office
// Everything technical lives behind the separate Developer tab.

// MARK: - ① Home — profile selector + system health

/// HOME — pick / add a profile (each is its own whole environment), set up Real-ID, and
/// see live System-health: your Wallet (phone), your Wearable (ring), your Server (node).
/// A System-ID is never shown; profiles lead by name only.
struct HomeTabView: View {
    @EnvironmentObject var session: AtlasSession
    @ObservedObject var ring: RingProbe
    @State private var newName = ""

    var body: some View {
        NavigationStack {
            List {
                profileSection
                identitySection
                healthSection
            }
            .navigationTitle("Home")
            .onAppear { session.checkServer() }
            .refreshable { session.checkServer() }
        }
    }

    // Profile selector — switch between your profiles or add a new one.
    private var profileSection: some View {
        Section {
            if session.personas.isEmpty {
                Text("No profiles yet — add one below.")
                    .font(.callout).foregroundStyle(.secondary)
            }
            ForEach(session.personas, id: \.handle) { p in
                Button { session.switchPersona(p) } label: {
                    HStack(spacing: 12) {
                        Image(systemName: "person.crop.circle.fill")
                            .font(.title2).foregroundStyle(.tint)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(p.username.isEmpty ? "unnamed" : p.username)
                                .font(.headline).foregroundStyle(.primary)
                            Text(session.isVerified(p) ? "Real-ID verified" : "pseudonym")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        if session.currentPersona?.handle == p.handle {
                            Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                        }
                    }
                }
            }
            HStack {
                TextField("New profile name", text: $newName)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                Button("Add") {
                    let n = newName.trimmingCharacters(in: .whitespaces)
                    guard !n.isEmpty else { return }
                    session.createPersona(n); newName = ""
                }
                .disabled(newName.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        } header: {
            Text("Profile")
        } footer: {
            Text("Separate, unlinkable environments.")
        }
    }

    // Real-ID: set up / add ID for the active profile (ePassport stand-in for now).
    @ViewBuilder private var identitySection: some View {
        if let p = session.currentPersona {
            Section("Identity") {
                NavigationLink {
                    PublicProfileEditor(personaKey: p.handle.map { String(format: "%02x", $0) }.joined(),
                                        username: p.username)
                } label: {
                    Label("Public profile", systemImage: "person.text.rectangle")
                }
                NavigationLink {
                    RecoverySharesView()
                } label: {
                    Label("Recovery shards", systemImage: "key.horizontal.fill")
                }
                NavigationLink {
                    DuressSettingsView()
                } label: {
                    Label("Safety / duress", systemImage: "shield.lefthalf.filled")
                }
                if session.isVerified(p) {
                    let tier = session.realIDTier(p) ?? "chip"
                    let issuerConfirmed = tier == "chip" && session.realIDIssuerConfirmed(p)
                    Label(tier != "chip" ? "ID scanned (barcode — document-stated)"
                            : issuerConfirmed ? "Real-ID verified (chip — issuer confirmed)"
                                              : "Real-ID verified (chip — issuer not confirmed)",
                          systemImage: issuerConfirmed ? "checkmark.seal.fill" : "checkmark.seal")
                        .foregroundStyle(issuerConfirmed ? .green : .orange)
                    if tier != "chip" {
                        NavigationLink { EIDScanView() } label: {
                            Label("Upgrade: scan a chip document (ePassport/eID)", systemImage: "wave.3.right")
                        }
                    }
                } else {
                    NavigationLink {
                        EIDScanView()
                    } label: {
                        Label("Verify Real-ID — scan a passport/eID chip", systemImage: "wave.3.right")
                    }
                    NavigationLink {
                        BarcodeIDScanView()
                    } label: {
                        Label("Or scan a driver's licence barcode (lower tier)", systemImage: "barcode.viewfinder")
                    }
                    Text("Optional, on-device, nothing stored or sent. Chip documents prove themselves cryptographically; a licence barcode only states its data — an honest lower tier.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }

    // System-health metrics: Wallet (phone) · Wearable (ring) · Server (node).
    private var healthSection: some View {
        Section {
            // Wallet (phone) = the CORE — the app runs on this alone (1-phone mode). The other
            // three are OPTIONAL add-ons; absent shows neutral (grey), not a warning.
            healthRow("Wallet (phone)", icon: "iphone",
                      ok: session.running, optional: false,
                      detail: session.running
                            ? (session.presenceLive ? "ambient mode · engine running (\(session.ratchetTicks) ticks)"
                                                     : "ambient mode · gated — move the phone")
                            : "set up ✓ · starting…")
            healthRow("Wearable / accessory", icon: "circle.circle",
                      ok: ring.pulsePresent, optional: true,
                      detail: ring.connectedName.isEmpty ? "optional · adds live presence"
                            : (ring.pulsePresent ? "live pulse ✓ — \(ring.connectedName)" : "connected, no pulse — \(ring.connectedName)"))
            NavigationLink {
                NodeSettingsView()
            } label: {
                healthRow("Node", icon: "desktopcomputer",
                          ok: session.nodeConnected, optional: true,
                          detail: session.nodeConnected ? "connected — \(session.nodeURL)"
                                : (session.groupOnline ? "connecting to \(session.nodeURL)…"
                                                       : "optional · tap to configure"))
            }
            healthRow("Network server", icon: "server.rack",
                      ok: session.serverReachable, optional: true,
                      detail: session.serverReachable
                            ? (session.serverBeaconRound > 0
                               ? "online — Zurich · beacon round \(session.serverBeaconRound)"
                               : "online — Zurich")
                            : "checking \(AtlasSession.publicServerURL)…")
        } header: {
            Text("System health")
        } footer: {
            Text("Atlas runs on your phone alone. Wearable, node and server are optional — they add presence and reach, they're not required.")
        }
    }

    private func healthRow(_ title: String, icon: String, ok: Bool, optional: Bool = false, detail: String) -> some View {
        HStack(spacing: 12) {
            Image(systemName: icon).font(.title3).frame(width: 28).foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).foregroundStyle(.primary)
                Text(detail).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Circle().fill(ok ? .green : (optional ? .secondary : .orange)).frame(width: 9, height: 9)
        }
    }
}

// MARK: - ③ Spaces — the cascading space graph for the active profile

/// SPACES — the active profile's space graph, Reddit-style cascade (vault root → folders /
/// chats / groups / market → nested spaces). "+" inside creates a child space.
struct SpacesTabView: View {
    @EnvironmentObject var session: AtlasSession
    @State private var path: [AppSpace] = []

    var body: some View {
        NavigationStack(path: $path) {
            Group {
                if let p = session.currentPersona {
                    SpaceNavigatorView(space: session.spaceRoot(for: p))
                } else {
                    ContentUnavailableView {
                        Label("No profile selected", systemImage: "person.crop.circle.badge.questionmark")
                    } description: {
                        Text("Pick a profile on the Home tab to open its spaces.")
                    }
                }
            }
            // MUST be INSIDE the NavigationStack to register. VALUE-BASED nav → pushed screens
            // survive the ~1s ratchet re-renders (no popping back to the vault).
            .navigationDestination(for: AppSpace.self) { SpaceNavigatorView(space: $0) }
        }
        // Reset the path when the persona changes → per-persona isolation, no churny `.id`.
        .onChange(of: session.currentPersona?.handle) { _, _ in path.removeAll() }
    }
}

// MARK: - ② Contacts

/// CONTACTS — search + save people, share your own contact by NFC. Backend (connect codes /
/// caller-ID / reachability) exists; this UI + CoreNFC share is the next build.
struct ContactsTabView: View {
    var body: some View { ContactsScreen() }
}

// MARK: - Market (ID-gated, top-level)

/// MARKET — a server-hosted listing space. Open to Real-ID-verified profiles only (no black
/// market): individuals and businesses list under their own name, with ledgered reviews and
/// ratings. Unverified profiles see the verify wall.
struct MarketTabView: View {
    @EnvironmentObject var session: AtlasSession

    var body: some View {
        NavigationStack {
            Group {
                if session.isCurrentProfileVerified {
                    comingSoon("Market", icon: "cart.fill",
                               detail: "Listings by named individuals and verified businesses — with ledgered transactions, reviews, reviews-of-reviews, 5-star ratings, and sort-by-credentials. Coming next.")
                } else {
                    VStack(spacing: 16) {
                        Image(systemName: "lock.shield").font(.system(size: 44)).foregroundStyle(.orange)
                        Text("The Market opens to ID-verified profiles")
                            .font(.headline).multilineTextAlignment(.center)
                        Text("Open to ID-verified profiles only — this keeps it Sybil-free and rules out a black market.")
                            .font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
                        Text("Government-ID verification (an on-device NFC scan of your ePassport / national eID — the phone reads the chip) is being wired in. Until it lands, no profile is verified, so the Market stays closed.")
                            .font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center)
                    }
                    .padding(32).frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
            .navigationTitle("Market")
        }
    }
}

// MARK: - Email / Camera / Office (honest scaffolds)

/// EMAIL — @clockwork-tree.com (or your own domain), openable from a contact, a space, or the
/// market. Scaffold — the mail backend is not wired yet.
struct EmailTabView: View {
    var body: some View {
        NavigationStack {
            comingSoon("Email", icon: "envelope.fill",
                       detail: "An @clockwork-tree.com address (or your own domain), reachable from contacts, spaces, and the market. Coming.")
                .navigationTitle("Email")
        }
    }
}

/// CHATS — a flat, consolidated list of EVERY chat you're in, gathered from across your whole
/// space graph (chats live inside spaces; this is the one place to find them all). Empty until
/// you start one inside a space.
struct ChatsTabView: View {
    @EnvironmentObject var session: AtlasSession
    var body: some View {
        NavigationStack {
            Group {
                if let root = session.currentRoot {
                    let chats = root.allChats()
                    if chats.isEmpty {
                        ContentUnavailableView("No chats", systemImage: "message")
                    } else {
                        List(chats) { c in
                            NavigationLink { MessagingView(chat: c) } label: {
                                HStack(spacing: 12) {
                                    Image(systemName: "message.fill").font(.title3).foregroundStyle(.tint)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(c.name).font(.headline)
                                        Text(c.messages.last?.text ?? "no messages yet")
                                            .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                                    }
                                }
                            }
                        }
                    }
                } else {
                    ContentUnavailableView("No profile selected", systemImage: "person.crop.circle.badge.questionmark",
                                           description: Text("Pick a profile on Home."))
                }
            }
            .navigationTitle("Chats")
        }
        // Per-persona isolation: rebuild for the active persona so only ITS chats show;
        // re-renders on graphRevision when a chat is created.
        .id(session.currentPersona?.handle)
    }
}

/// CAPTURE — record camera / video / audio straight into your default media folder in the
/// vault (the device-hardware warehouse). The default folder is selectable — pick any folder.
struct CaptureTabView: View {
    @EnvironmentObject var session: AtlasSession
    @State private var showFolderPicker = false

    var body: some View {
        NavigationStack {
            Group {
                if let folder = session.defaultCaptureFolder() {
                    // Observe the folder itself so captured items appear immediately.
                    CaptureIntoFolderView(folder: folder) { showFolderPicker = true }
                } else {
                    ContentUnavailableView("Pick a profile", systemImage: "person.crop.circle.badge.questionmark",
                                           description: Text("Select a profile on Home to capture."))
                }
            }
            .navigationTitle("Capture")
            .sheet(isPresented: $showFolderPicker) { CaptureFolderPicker().environmentObject(session) }
        }
    }
}

/// Capture UI bound to a specific folder — `@ObservedObject` so a saved item shows up live.
struct CaptureIntoFolderView: View {
    @EnvironmentObject var session: AtlasSession
    @ObservedObject var folder: AppSpace
    var pickFolder: () -> Void

    var body: some View {
        VStack(spacing: 16) {
            Button(action: pickFolder) {
                VStack(spacing: 2) {
                    Text("Saving to").font(.caption).foregroundStyle(.secondary)
                    Label(folder.name, systemImage: "folder.fill").font(.headline)
                }
            }.padding(.top)

            CaptureControls(space: folder, routeByType: true).padding(.horizontal)

            if folder.items.isEmpty {
                Spacer()
                Text("No items").font(.callout).foregroundStyle(.secondary)
                Spacer()
            } else {
                List {
                    Section("Recent in \(folder.name) (\(folder.items.count))") {
                        ForEach(Array(folder.items.suffix(12).reversed())) { it in
                            Label(it.vaultName, systemImage: icon(it.kind))
                        }
                    }
                }
            }
        }
    }

    private func icon(_ kind: String) -> String {
        switch kind {
        case "image": return "photo"; case "video": return "film"; case "audio": return "waveform"
        case "pdf": return "doc.richtext"; case "text": return "doc.text"; default: return "doc"
        }
    }
}

/// Choose which folder the Capture tab saves into (any folder in your vault graph).
struct CaptureFolderPicker: View {
    @EnvironmentObject var session: AtlasSession
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        NavigationStack {
            List {
                if let root = session.currentRoot {
                    ForEach(root.allFolders()) { f in
                        Button { session.setDefaultCaptureFolder(f.id); dismiss() } label: {
                            HStack {
                                Label(f.name, systemImage: "folder")
                                Spacer()
                                if session.defaultCaptureFolderID == f.id { Image(systemName: "checkmark").foregroundStyle(.green) }
                            }
                        }
                    }
                }
            }
            .navigationTitle("Default capture folder")
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Done") { dismiss() } } }
        }
    }
}

/// OFFICE — create documents (saved into your vault) and see every document across your
/// spaces in one place. Save-as-PDF / ONLYOFFICE editing come next; creating + storing is real.
struct OfficeTabView: View {
    @EnvironmentObject var session: AtlasSession
    @State private var editing: DocEditTarget?

    var body: some View {
        NavigationStack {
            Group {
                if let root = session.currentRoot {
                    docList(root)
                } else {
                    ContentUnavailableView("Pick a profile", systemImage: "person.crop.circle.badge.questionmark",
                                           description: Text("Select a profile on Home."))
                }
            }
            .navigationTitle("Office")
            .sheet(item: $editing) { t in
                DocumentEditorView(space: t.space, existingVaultName: t.vaultName).environmentObject(session)
            }
        }
    }

    private func docs(_ root: AppSpace) -> [SpaceItem] {
        root.allFolders().flatMap { $0.items }.filter { ["doc", "text", "pdf"].contains($0.kind) }
    }

    @ViewBuilder private func docList(_ root: AppSpace) -> some View {
        let items = docs(root)
        List {
            Section {
                Button { editing = DocEditTarget(space: root, vaultName: nil) } label: {
                    Label("New document", systemImage: "doc.badge.plus")
                }
            }
            Section("Documents") {
                if items.isEmpty { Text("No documents").font(.callout).foregroundStyle(.secondary) }
                ForEach(items) { d in docRow(d, root: root) }
            }
        }
    }

    @ViewBuilder private func docRow(_ d: SpaceItem, root: AppSpace) -> some View {
        if d.kind == "doc" {
            Button { editing = DocEditTarget(space: root, vaultName: d.vaultName) } label: {
                Label(d.vaultName, systemImage: "doc.text.fill").foregroundStyle(.primary)
            }
        } else if let vf = session.vaultFiles.first(where: { $0.name == d.vaultName }) {
            NavigationLink { ContentViewerView(file: vf) } label: { Label(d.vaultName, systemImage: "doc.text") }
        } else {
            Label(d.vaultName, systemImage: "doc.text").foregroundStyle(.secondary)
        }
    }
}

// MARK: - shared

/// A clean, honest placeholder — says what the screen WILL be, no scary banners.
@ViewBuilder
func comingSoon(_ title: String, icon: String, detail: String) -> some View {
    ContentUnavailableView {
        Label(title, systemImage: icon)
    } description: {
        Text(detail)
    }
}
