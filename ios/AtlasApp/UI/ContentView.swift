import SwiftUI

/// App root — one enrolment gate in front of everything. Until the session is
/// enrolled you see only the enrol ritual; after, the enrolled identity + live
/// presence unlock all the features (each now reads the shared `AtlasSession`).
struct ContentView: View {
    @EnvironmentObject var session: AtlasSession

    var body: some View {
        // Product-first: no persistent proof-of-concept strip on every screen. The
        // four primary tabs lead; every dev/diagnostic screen (and Spaces, for now)
        // is pushed into iOS's automatic "More" overflow so it stays reachable but
        // never front-and-centre. The one remaining "Beta" note lives in Profile.
        if session.enrolled {
            // Left-side vertical, scrollable, user-reorderable nav rail — every destination is
            // always visible (Home, Spaces, Chats, Contacts, Email, Market, Capture, Office,
            // Developer); no bottom bar, no "More (…)" overflow. See AppShell.
            AppShell()
        } else if session.canRestore {
            UnlockView()   // an enrolled session exists on this device — Face ID unlocks it (#37)
        } else {
            EnrolView()
        }
    }
}

/// Relaunch unlock: an enrolled session is sealed on this device — Face ID (the Secure Enclave
/// release) restores it. Disenrolling from inside wipes the sealed session; "Start over" here
/// abandons it and returns to a fresh enrol.
struct UnlockView: View {
    @EnvironmentObject var session: AtlasSession
    @State private var busy = false
    @State private var showRecover = false
    @State private var code = ""
    @State private var wrong = false

    private var gated: Bool { session.duressRequireCode && session.duressConfigured }

    var body: some View {
        VStack(spacing: 24) {
            Spacer()
            Image("AtlasLogo").resizable().scaledToFit()
                .frame(width: 132, height: 132)
                .accessibilityLabel("Atlas")
            Text("Welcome back").font(.title2.bold())
            if gated {
                Text("Unlock with Face ID and your access code.")
                    .font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
                    .padding(.horizontal, 40)
                SecureField("Access code", text: $code)
                    .textFieldStyle(.roundedBorder)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                    .frame(maxWidth: 240).multilineTextAlignment(.center)
                if wrong { Text("Incorrect code").font(.caption).foregroundStyle(.red) }
                Button {
                    unlock()
                } label: {
                    Label(busy ? "Unlocking…" : "Unlock", systemImage: "lock.open")
                        .font(.headline).padding(.horizontal, 28).padding(.vertical, 12)
                }
                .buttonStyle(.borderedProminent).disabled(busy || code.isEmpty)
            } else {
                Text("Your Atlas session is sealed on this device. Unlock it with Face ID.")
                    .font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
                    .padding(.horizontal, 40)
                Button {
                    busy = true
                    Task { @MainActor in session.restoreSession(); busy = false }
                } label: {
                    Label(busy ? "Unlocking…" : "Unlock", systemImage: "lock.open")
                        .font(.headline).padding(.horizontal, 28).padding(.vertical, 12)
                }
                .buttonStyle(.borderedProminent).disabled(busy)
            }
            Spacer()
            Button("Recover from shards (new phone)") { showRecover = true }
                .font(.footnote)
            Button("Start over (new enrolment)", role: .destructive) { session.disenrol() }
                .font(.footnote)
                .padding(.bottom, 24)
        }
        .sheet(isPresented: $showRecover) { RecoverFromShardsView().environmentObject(session) }
        .onAppear {
            // Only auto-prompt Face ID when there's no code gate; gated unlock waits for the code.
            if !gated { Task { @MainActor in session.restoreSession() } }
        }
    }

    private func unlock() {
        wrong = false; busy = true
        let entered = code; code = ""
        Task { @MainActor in
            // Panic PHRASE at the lock screen = duress unlock (decoy + witness) — a second trigger
            // beside the panic code, for when you can't cleanly enter the code under pressure.
            if session.matchesPanicPhrase(entered) {
                await session.triggerDuress(code: entered); busy = false; return
            }
            switch session.evaluateUnlockCode(entered) {
            case .normal:  session.restoreSession()          // Face ID (SE release) happens here
            case .duress:  await session.triggerDuress(code: entered)  // lock + evidence + decoy persona
            case .invalid: wrong = true
            }
            busy = false
        }
    }
}

/// The full disclaimer + status disclosure. Presented as a sheet from the "About
/// Atlas" link in Profile — the single remaining home for the proof-of-concept
/// disclosure. The detailed real/stood-in/stubbed list comes from
/// `AtlasFlags.honestyBanner`.
struct DisclaimerView: View {
    var inSheet = false
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        NavigationStack {
            List {
                Section {
                    Label("Proof of concept — work in progress", systemImage: "exclamationmark.triangle.fill")
                        .font(.headline).foregroundStyle(.orange)
                    Text(AtlasFlags.disclaimer)
                        .font(.callout).foregroundStyle(.secondary)
                }
                Section("What is real vs. stood-in vs. stubbed") {
                    ForEach(AtlasFlags.honestyBanner, id: \.self) {
                        Text($0).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            .navigationTitle("Disclaimer")
            .toolbar {
                if inSheet {
                    ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
                }
            }
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
                Section("Status disclosure (full disclaimer on the Disclaimer tab)") {
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
