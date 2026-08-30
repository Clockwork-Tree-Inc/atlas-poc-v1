import SwiftUI
import AtlasCore

/// Home — pick the persona you're acting as, and a live read on whether the system is
/// functioning. The persona you select owns its OWN vault/spaces/life ("from vault onward");
/// switching re-opens that persona's stack. Personas are mutually unlinkable and unlinkable
/// to the real you — the System-ID link never surfaces here (only opaque handles).
struct HomeView: View {
    @EnvironmentObject var session: AtlasSession
    @State private var checkResults: [SystemCheck.Result] = []
    @State private var ranCheck = false

    private func hex(_ d: Data, _ n: Int = 4) -> String {
        d.prefix(n).map { String(format: "%02x", $0) }.joined()
    }
    private var checkOK: Bool { ranCheck && checkResults.allSatisfy { $0.ok } }

    // The ONE Real-ID slot = the (at most one) PUBLIC-tier persona; pseudonyms = the rest.
    private var realIDPersona: Profile? { session.personas.first { $0.tier == .public } }
    private var pseudonyms: [Profile] { session.personas.filter { $0.tier != .public } }

    var body: some View {
        NavigationStack {
            List {
                statusSection
                recoverySection
                realIDSection
                pseudonymsSection
                conformanceSection
            }
            .navigationTitle("Home")
        }
    }

    // MARK: system functioning

    private var statusSection: some View {
        Section {
            statusRow("Enrolled", session.enrolled)
            statusRow("Live presence",
                      session.presenceLive && !session.presenceLocked,
                      detail: session.presenceLocked ? "LOCKED" : (session.presenceLive ? "present" : "waiting"))
            statusRow("Session running", session.running, detail: "\(session.ratchetTicks) ticks")
            statusRow("Vault open", session.vault != nil)
            statusRow("Node / peers",
                      !session.roster.isEmpty || session.peerLive,
                      detail: session.roster.isEmpty ? session.nodeURL : "\(session.roster.count) online")
            LabeledContent("Liveness tier", value: session.enrolTier.label)
        } header: {
            Text("System status")
        }
    }

    private func statusRow(_ title: String, _ ok: Bool, detail: String? = nil) -> some View {
        HStack {
            Image(systemName: ok ? "checkmark.circle.fill" : "circle")
                .foregroundStyle(ok ? .green : .secondary)
            Text(title)
            Spacer()
            if let detail { Text(detail).font(.caption).foregroundStyle(.secondary) }
        }
    }

    // MARK: personas

    /// A tappable persona row (switch to it; marks the active one).
    private func personaRow(_ p: Profile, icon: String, kind: String) -> some View {
        let active = p.handle == session.currentPersona?.handle
        return Button { session.switchPersona(p) } label: {
            HStack {
                Image(systemName: icon).foregroundStyle(active ? .green : .blue)
                VStack(alignment: .leading, spacing: 2) {
                    Text(hex(p.handle, 6)).font(.body.monospaced())      // the CODE is the persona identity
                    Text(kind).font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Text(active ? "active" : "switch").font(.caption)
                    .foregroundStyle(active ? .green : .blue)
            }
        }
    }

    // ONE recovery account (recovery-only — you don't act as it).
    private var recoverySection: some View {
        Section {
            HStack {
                Image(systemName: "externaldrive.badge.key").foregroundStyle(.orange)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Recovery account")
                    Text("recovery only · never Real-ID'd").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
            }
        } header: {
            Text("Recovery")
        } footer: {
            Text("One recovery account — used only to rebuild your identity if you lose your device. You never act as it. (Manage on the Recovery tab.)")
        }
    }

    // ONE Real ID (optional, one per person).
    private var realIDSection: some View {
        Section {
            if let rid = realIDPersona {
                personaRow(rid, icon: "checkmark.seal.fill", kind: "Real ID · unverified")
            } else {
                Button {
                    session.createPersona("real-id", tier: .public)
                } label: {
                    Label("Set up your Real ID", systemImage: "person.badge.shield.checkmark")
                }
            }
        } header: {
            Text("Real ID — one per person, optional")
        } footer: {
            Text("Expose a verified identity only for ID-gated spaces. Optional — everything works anonymously without it. Government-document verification comes with the paid entitlement; until then this is the reserved slot.")
        }
    }

    // MANY pseudonyms + a "+" to add.
    private var pseudonymsSection: some View {
        Section {
            if pseudonyms.isEmpty {
                Text("no pseudonyms yet").font(.footnote).foregroundStyle(.secondary)
            }
            ForEach(pseudonyms.indices, id: \.self) { i in
                personaRow(pseudonyms[i], icon: "person.crop.circle", kind: "pseudonym")
            }
            Button {
                session.createPersona("pseudonym-\(pseudonyms.count)", tier: .anonymous)
            } label: {
                Label("Add pseudonym", systemImage: "plus.circle.fill")
            }
        } header: {
            Text("Pseudonyms")
        } footer: {
            Text("Add as many unlinkable pseudonyms as you like — each is identified by its CODE and owns its own vault, messaging, and history. Tap one to act as it.")
        }
    }

    // MARK: conformance (Swift <-> Python parity self-test)

    private var conformanceSection: some View {
        Section {
            HStack {
                Image(systemName: ranCheck ? (checkOK ? "checkmark.seal.fill" : "xmark.seal.fill") : "seal")
                    .foregroundStyle(ranCheck ? (checkOK ? .green : .red) : .secondary)
                Text(ranCheck ? (checkOK ? "All systems green" : "Attention needed") : "Not checked")
                Spacer()
                Button("Run check") { checkResults = SystemCheck.run(); ranCheck = true }
            }
            if ranCheck {
                Text(SystemCheck.summary(checkResults)).font(.caption).foregroundStyle(.secondary)
            }
        } header: {
            Text("Conformance (Swift ↔ Python parity)")
        } footer: {
            Text("Runs the on-device crypto self-test. Green = this device's Swift crypto is byte-identical to the Python reference-of-record. The deeper signed proof is on the System Integrity tab.")
        }
    }
}
