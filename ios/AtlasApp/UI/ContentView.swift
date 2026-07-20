import SwiftUI

/// App root — one enrolment gate in front of everything. Until the session is
/// enrolled you see only the enrol ritual; after, the enrolled identity + live
/// presence unlock all the features (each now reads the shared `AtlasSession`).
struct ContentView: View {
    @EnvironmentObject var session: AtlasSession

    var body: some View {
        if session.enrolled {
            TabView {
                MessagingView()
                    .tabItem { Label("Messaging", systemImage: "lock.message") }
                VaultView()
                    .tabItem { Label("Vault", systemImage: "lock.doc") }
                CaptureLedgerView()
                    .tabItem { Label("Capture", systemImage: "camera.badge.clock") }
                RecoveryView()
                    .tabItem { Label("Recovery", systemImage: "externaldrive.badge.key") }
                DuressView()
                    .tabItem { Label("Duress", systemImage: "exclamationmark.shield") }
                RingDiagnosticsView()
                    .tabItem { Label("Ring", systemImage: "circle.circle") }
                SessionView()
                    .tabItem { Label("Session", systemImage: "person.crop.circle.badge.checkmark") }
                DiagnosticsView()
                    .tabItem { Label("Diag", systemImage: "bolt.batteryblock") }
            }
        } else {
            EnrolView()
        }
    }
}

/// Post-enrol home: the live session (self-advancing ratchet, presence) + who you
/// are + lock/disenrol. The LK / continuity value is never shown — fully private.
struct SessionView: View {
    @EnvironmentObject var session: AtlasSession
    @State private var handleApp = "…"
    @State private var handleMsg = "…"
    @State private var handleLedger = "…"

    private func refreshHandles() {
        func h(_ ctx: String) -> String {
            (session.contextPseudonym(ctx)?.handle.prefix(6).map { String(format: "%02x", $0) }.joined() ?? "—") + "…"
        }
        handleApp = h("app:service"); handleMsg = h("msg:peer"); handleLedger = h("ledger")
    }

    var body: some View {
        NavigationStack {
            List {
                if session.presenceLocked {
                    Section {
                        Label("HARD LOCKDOWN — live presence lost", systemImage: "lock.trianglebadge.exclamationmark")
                            .font(.subheadline.bold()).foregroundStyle(.red)
                        Text("The ring came off (beyond the grace window). The live keys were wiped; your sealed identity is intact. Wear the ring again and re-enter to rebuild the live session.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                Section("Live session (group)") {
                    HStack {
                        Circle().fill(session.peerLive ? .green : .orange).frame(width: 8, height: 8)
                        Text(session.peerLive
                             ? "LIVE — \(session.roster.count + 1) online"
                             : "waiting for others to come online…").font(.footnote.bold())
                    }
                    if !session.roster.isEmpty {
                        Text("in session: \(([session.username] + session.roster).joined(separator: ", "))")
                            .font(.caption.monospaced()).foregroundStyle(.secondary)
                    }
                    if session.peerLive {
                        if !session.safetyNumber.isEmpty {
                            VStack(alignment: .leading, spacing: 2) {
                                Label("safety number", systemImage: "checkmark.shield")
                                    .font(.caption.bold()).foregroundStyle(.green)
                                Text(session.safetyNumber)
                                    .font(.body.monospaced().bold()).textSelection(.enabled)
                                Text("Read this aloud with the others — if everyone's matches, the relay is not a man-in-the-middle. Each member's KEM key is identity-signed, so the node can't swap keys without also forging identities, which would change this number.")
                                    .font(.caption2).foregroundStyle(.secondary)
                            }
                        }
                        Text("continuity ratchet: \(session.ratchetTicks) advances")
                            .font(.footnote.monospaced())
                        Text("presence: \(session.presenceLive ? "PRESENT ✓" : "gated — move the phone/wear the ring")")
                            .font(.footnote).foregroundStyle(session.presenceLive ? .green : .orange)
                    }
                    Text("The system only comes alive when BOTH phones are online and co-derive the live LK. The epoch key wraps that LK (presence-released); the LK itself is never shown. The ratchet then advances on its own — no buttons.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section("Anonymous identity — derived pseudonyms") {
                    Text("System-ID: never shown (anonymous root)")
                        .font(.caption).foregroundStyle(.secondary)
                    Text("service handle: \(handleApp)").font(.caption.monospaced())
                    Text("message handle: \(handleMsg)").font(.caption.monospaced())
                    Text("ledger handle:  \(handleLedger)").font(.caption.monospaced())
                    Text("epoch \(session.pseudonymEpoch) · each context gets a distinct, uncorrelatable handle, all derived from (and resolvable only under cause to) the one System-ID.")
                        .font(.caption2).foregroundStyle(.secondary)
                    Button("Rotate System-ID (fresh unlinkable handles)") {
                        session.rotateSystemID(); refreshHandles()
                    }
                }
                Section("Honest status") {
                    ForEach(AtlasFlags.honestyBanner, id: \.self) {
                        Text($0).font(.caption2).foregroundStyle(.secondary)
                    }
                }
                Section {
                    Button("Lock / disenrol", role: .destructive) { session.disenrol() }
                }
                Section("Log") {
                    ForEach(Array(session.log.enumerated().reversed()), id: \.offset) { _, l in
                        Text(l).font(.caption2.monospaced())
                    }
                }
            }
            .navigationTitle("Session")
            .onAppear { refreshHandles() }
        }
    }
}
