import SwiftUI

/// Safety / duress — the coercion channel (Axiom 5). Face ID proves WHO; the access code proves
/// FREE WILL. A panic code (a different code you set at enrol) never errors — it starts a
/// continuous witness and applies the response you choose here. A watcher can't tell a normal
/// unlock from a duress unlock.
struct DuressSettingsView: View {
    @EnvironmentObject var session: AtlasSession
    @State private var requireCode = true
    @State private var response: AtlasSession.DuressResponse = .decoy
    @State private var phrase = ""
    @State private var capMB = 200
    @State private var decoyName = ""
    @State private var decoyPanic = ""
    @State private var newContact = ""
    @State private var newContactGuardian = false

    var body: some View {
        Form {
            requireSection
            if requireCode {
                responseSection
                if response == .decoy { decoySection }
                phraseSection
                budgetSection
            }
            trustedContactsSection
            notificationSection
            statusSection
        }
        .navigationTitle("Safety / duress")
        .onAppear {
            requireCode = session.duressRequireCode
            response = session.duressResponse
            capMB = session.witnessCapBytes / (1024 * 1024)
        }
        .onChange(of: requireCode) { _, v in session.duressRequireCode = v }
        .onChange(of: response) { _, v in session.duressResponse = v }
        .onChange(of: capMB) { _, v in session.witnessCapBytes = v * 1024 * 1024 }
    }

    @ViewBuilder private var requireSection: some View {
        Section {
            Toggle("Require access code on unlock", isOn: $requireCode)
        } footer: {
            Text(requireCode
                 ? "Face ID + code on every unlock. This is what makes a panic code possible — a coercer who Face-IDs you in still can't tell your normal code from your duress code."
                 : "⚠️ Off: Face ID alone unlocks. This REMOVES duress protection — there is no moment to enter a panic code.")
        }
    }

    @ViewBuilder private var responseSection: some View {
        Section {
            Picker("Response", selection: $response) {
                Text("Decoy persona (show a chosen persona)").tag(AtlasSession.DuressResponse.decoy)
                Text("Wipe (destroy real key — permanent)").tag(AtlasSession.DuressResponse.wipe)
                Text("Leave as is (open real, flag silently)").tag(AtlasSession.DuressResponse.silent)
            }
            .pickerStyle(.inline)
        } header: {
            Text("If I enter my panic code")
        } footer: {
            Text("The witness always runs. The response above is only what the app SHOWS a watcher.")
        }
    }

    @ViewBuilder private var decoySection: some View {
        Section {
            if session.personas.isEmpty {
                Text("No personas yet — create one to use as your decoy.")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                Picker("Decoy persona", selection: $decoyName) {
                    ForEach(session.personas, id: \.username) { p in Text(p.username).tag(p.username) }
                }
                SecureField("Panic code (to confirm)", text: $decoyPanic)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                Button("Set as decoy") {
                    if let p = session.personas.first(where: { $0.username == decoyName }) {
                        session.setDuressDecoy(p, panicCode: decoyPanic); decoyPanic = ""
                    }
                }
                .disabled(decoyName.isEmpty || decoyPanic.isEmpty)
            }
        } header: {
            Text("Decoy persona (shown under duress)")
        } footer: {
            Text("Pick a persona you ACTUALLY use — one whose contents you're willing to reveal. A panic-code unlock opens ONLY this persona, with its real history, and never your others or your root. A persona you use is plausible to a coercer; an empty one isn't.")
        }
    }

    @ViewBuilder private var phraseSection: some View {
        Section {
            SecureField(phrasePlaceholder, text: $phrase)
            Button("Save phrase") {
                session.setPanicPhrase(phrase); phrase = ""
            }
            .disabled(phrase.trimmingCharacters(in: .whitespaces).isEmpty)
            if session.hasPanicPhrase {
                Button("Clear phrase", role: .destructive) { session.setPanicPhrase("") }
                Toggle("Listen for it spoken (hands-free)", isOn: Binding(
                    get: { session.voicePanicEnabled },
                    set: { session.voicePanicEnabled = $0 }))
            }
        } header: {
            Text("Panic phrase")
        } footer: {
            Text("Type it in any chat/AI box to silently start the witness. Turn on ‘Listen for it spoken’ to also trigger it HANDS-FREE by voice — recognized ON DEVICE (never sent anywhere). Note: while listening, iOS shows the orange mic dot and it uses more battery, so a watcher can tell the mic is on — leave it off unless you want the hands-free trigger.")
        }
    }

    private var phrasePlaceholder: String {
        session.hasPanicPhrase ? "•••••• (set — tap to change)" : "Set a panic phrase"
    }

    @ViewBuilder private var budgetSection: some View {
        Section {
            Picker("Vault budget", selection: $capMB) {
                Text("50 MB").tag(50)
                Text("200 MB").tag(200)
                Text("500 MB").tag(500)
                Text("2 GB").tag(2048)
            }
        } header: {
            Text("Witness recording budget")
        } footer: {
            Text("The witness streams continuously (location, network, motion, ambient audio) into your vault and your node until this much is recorded or the phone powers off. Bigger budget = longer black box.")
        }
    }

    @ViewBuilder private var trustedContactsSection: some View {
        Section {
            ForEach(session.panicContacts) { c in
                HStack {
                    Image(systemName: c.guardian ? "eye.trianglebadge.exclamationmark.fill" : "bell.fill")
                        .foregroundStyle(c.guardian ? .orange : .secondary)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(c.name)
                        Text(c.guardian ? "alerted + can collect forensics (both must agree)" : "alerted with your location")
                            .font(.caption2).foregroundStyle(.secondary)
                    }
                }
            }
            .onDelete { idx in idx.map { session.panicContacts[$0].name }.forEach(session.removePanicContact) }

            HStack {
                TextField("Name (a contact you message)", text: $newContact)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                Button("Add") {
                    session.addPanicContact(newContact, guardian: newContactGuardian)
                    newContact = ""; newContactGuardian = false
                }
                .disabled(newContact.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            Toggle("Also let them collect my forensics", isOn: $newContactGuardian)
        } header: {
            Text("Trusted contacts (panic)")
        } footer: {
            Text("When you set off panic, these people are told you're in danger and WHERE you are. A ‘collect forensics’ guardian can also retrieve your black-box recording — but only under MUTUAL CONSENT: they hold half the key from now, and your other half is released only the moment you trigger panic. Neither half alone opens anything.")
        }
    }

    @ViewBuilder private var notificationSection: some View {
        Section {
            Toggle("Live push notifications", isOn: Binding(
                get: { session.pushEnabled },
                set: { session.pushEnabled = $0 }))
        } header: {
            Text("Notifications")
        } footer: {
            Text(session.pushEnabled
                 ? "On: you get a buzz when a message lands, even with Atlas closed. Apple relays a content-free wake, so Apple learns your device is an Atlas user + when you receive activity (never content or sender)."
                 : "Off (default): Atlas never contacts Apple — you see messages when you open the app. Maximum privacy; no live buzz.")
        }
    }

    @ViewBuilder private var statusSection: some View {
        Section {
            if session.duressConfigured {
                Label("Duress codes armed", systemImage: "checkmark.shield.fill").foregroundStyle(.green)
            } else {
                Label("Set your codes at enrolment", systemImage: "exclamationmark.shield")
                    .foregroundStyle(.orange)
                Text("This identity predates the duress-code gate — re-enrol to set a normal code + a panic code.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if session.witnessActive {
                Label("WITNESS ACTIVE — \(session.witnessFrames) frames", systemImage: "record.circle")
                    .foregroundStyle(.red)
                Button("Stop witness", role: .destructive) { session.stopDuressWitness(reason: "user") }
            }
            Text("Future: danger-sensing wearables (abnormal vitals / distress) will escalate to this same witness automatically.")
                .font(.caption2).foregroundStyle(.secondary)
        }
    }
}
