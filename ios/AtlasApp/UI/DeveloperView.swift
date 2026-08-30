import SwiftUI

/// DEVELOPER — every technical / diagnostic / proof-of-concept screen in ONE place, out
/// of the consumer product. The product tabs stay clean; anything a builder needs (session
/// internals, presence/hardware rigs, integrity checks, PoC milestones) lives behind here.
///
/// Topped with a dated CHANGE LOG so what shipped, and when, is visible in-app. Newest
/// entries go at the TOP of `changelog` — one line per user-meaningful change.
struct DeveloperView: View {
    @EnvironmentObject var session: AtlasSession

    struct Change: Identifiable {
        let id = UUID()
        let date: String        // yyyy-MM-dd
        let summary: String
    }

    /// NEWEST FIRST. Add a new entry at the top each time something user-visible changes.
    private let changelog: [Change] = [
        .init(date: "2026-08-11", summary: "Developer tab + in-app change log; product shell is a single Profiles entry that cascades into spaces."),
        .init(date: "2026-08-11", summary: "Fixed the space-navigation crash (nested navigation stacks in embedded Vault/Messaging) and removed the duplicate identity/naming tab."),
        .init(date: "2026-08-11", summary: "Space spine: everything is a recursive, kinded space (vault/folder/chat/group/market); the market is server-hosted and ID-gated — no black market."),
        .init(date: "2026-08-11", summary: "Beta economy: receipts-not-tokens mode gate (no live token until full release) + docs reframed for beta."),
        .init(date: "2026-08-11", summary: "AI: model-agnostic seam (open-weights only) + provenance trail + author-citation economy."),
        .init(date: "2026-08-10", summary: "Economy, private transport (batching/padding/Tor seam), ledger/anchor seam, contacts & discovery — Python + Swift parity."),
        .init(date: "2026-08-10", summary: "Personas & spaces stack + interop + zero-knowledge person-tag, mirrored into iOS."),
        .init(date: "2026-07-26", summary: "In-app hardware Seams test harness + lab notebook."),
        .init(date: "2026-07-25", summary: "Debug-parallel hardware-test rig (collector + scorers + guided runner)."),
    ]

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ForEach(changelog) { c in
                        VStack(alignment: .leading, spacing: 3) {
                            Text(c.date)
                                .font(.caption.monospaced().bold())
                                .foregroundStyle(.tint)
                            Text(c.summary)
                                .font(.callout)
                                .foregroundStyle(.primary)
                        }
                        .padding(.vertical, 2)
                    }
                } header: {
                    Label("Change log", systemImage: "clock.arrow.circlepath")
                } footer: {
                    Text("Newest first. These are developer-facing notes — the consumer product carries none of this.")
                }

                Section("Identity & live session") {
                    devLink("Session internals", "person.crop.circle.badge.checkmark") { SessionView() }
                    devLink("Account recovery", "externaldrive.badge.key") { RecoveryView() }
                    devLink("Duress", "exclamationmark.shield") { DuressView() }
                }

                Section("Presence & hardware") {
                    devLink("Ring diagnostics", "circle.circle") { RingDiagnosticsView() }
                    devLink("Handshake / ring bind", "hand.raised") { HandshakeBindView(ring: session.ring) }
                    devLink("Ambient entropy", "waveform") { AmbientPoCView() }
                }

                Section("Integrity & diagnostics") {
                    devLink("System integrity", "checkmark.shield") { SystemHealthView() }
                    devLink("Developer log", "doc.text.below.ecg") { DevLogView() }
                    devLink("Diagnostics", "bolt.batteryblock") { DiagnosticsView() }
                    devLink("Hardware seams", "checklist") { HardwareSeamsView() }
                    devLink("Capture ledger", "camera.badge.clock") { CaptureLedgerView() }
                }

                Section("Proof-of-concept milestones") {
                    devLink("Milestone 1", "1.circle") { Milestone1View() }
                    devLink("Milestone 2", "2.circle") { Milestone2View() }
                    devLink("PoC dashboard", "house") { HomeView() }
                }

                Section {
                    devLink("Full disclosure (what's real / stood-in / stubbed)", "info.circle") { DisclaimerView() }
                }
            }
            .navigationTitle("Developer")
        }
    }

    /// A row that pushes a technical screen. `@ViewBuilder` so each destination is built lazily.
    private func devLink<Destination: View>(_ title: String, _ icon: String,
                                            @ViewBuilder _ destination: @escaping () -> Destination) -> some View {
        NavigationLink { destination() } label: { Label(title, systemImage: icon) }
    }
}
