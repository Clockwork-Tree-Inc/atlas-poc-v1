import SwiftUI
import AtlasCore

/// The product-facing identity screen. This is where a person sees WHO THEY ARE by
/// NAME (never a raw hex handle up front), names and switches their personas, and
/// claims a human-readable name. Any technical/cryptographic detail is tucked behind
/// a collapsed "Technical details" disclosure so codes never lead the experience.
struct ProfileView: View {
    @EnvironmentObject var session: AtlasSession
    @State private var newPersonaName = ""
    @State private var nameToClaim = ""
    @State private var showAbout = false

    /// The name to show at the top: the claimed human-readable name if set, else the
    /// current persona's chosen username. Falls back to a friendly placeholder.
    private var displayName: String {
        if let claimed = session.claimedName, !claimed.isEmpty { return claimed }
        if let u = session.currentPersona?.username, !u.isEmpty { return u }
        return "You"
    }

    private func hex(_ data: Data, _ n: Int = 6) -> String {
        data.prefix(n).map { String(format: "%02x", $0) }.joined() + "…"
    }

    var body: some View {
        NavigationStack {
            List {
                // WHO YOU ARE — name first, big, no codes.
                Section {
                    VStack(alignment: .leading, spacing: 6) {
                        HStack(spacing: 12) {
                            Image(systemName: "person.crop.circle.fill")
                                .font(.largeTitle).foregroundStyle(.tint)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(displayName)
                                    .font(.title2.bold())
                                if session.claimedName == nil {
                                    Text("acting as “\(session.currentPersona?.username ?? "me")”")
                                        .font(.caption).foregroundStyle(.secondary)
                                } else {
                                    Text("claimed name")
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                    .padding(.vertical, 4)
                }

                // CLAIM A NAME — a human-readable address for the current persona.
                Section {
                    HStack {
                        TextField("Claim a name (e.g. alex)", text: $nameToClaim)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        Button("Claim") {
                            if session.claimName(nameToClaim) { nameToClaim = "" }
                        }
                        .disabled(nameToClaim.trimmingCharacters(in: .whitespaces).isEmpty)
                    }
                } header: {
                    Text("Your name")
                } footer: {
                    Text("A name others can find you by. It’s signed by your key, so only you can claim it.")
                }

                // PERSONAS — listed BY NAME, tap to switch, plus create+name a new one.
                Section {
                    ForEach(session.personas, id: \.handle) { persona in
                        Button {
                            session.switchPersona(persona)
                        } label: {
                            HStack {
                                Image(systemName: "person.fill")
                                    .foregroundStyle(.secondary)
                                Text(persona.username.isEmpty ? "unnamed" : persona.username)
                                    .foregroundStyle(.primary)
                                Spacer()
                                if persona.handle == session.currentPersona?.handle {
                                    Image(systemName: "checkmark.circle.fill")
                                        .foregroundStyle(.tint)
                                }
                            }
                        }
                    }
                    HStack {
                        TextField("New persona name", text: $newPersonaName)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        Button("Create") {
                            let n = newPersonaName.trimmingCharacters(in: .whitespaces)
                            guard !n.isEmpty else { return }
                            session.createPersona(n)
                            newPersonaName = ""
                        }
                        .disabled(newPersonaName.trimmingCharacters(in: .whitespaces).isEmpty)
                    }
                } header: {
                    Text("Personas")
                } footer: {
                    Text("Each persona is a separate identity with its own vault, chats, and space — unlinkable to your others.")
                }

                // TECHNICAL DETAIL — collapsed by default, so hex never leads.
                Section {
                    DisclosureGroup("Technical details") {
                        if let p = session.currentPersona {
                            LabeledContent("Persona handle", value: hex(p.handle))
                                .font(.caption.monospaced())
                        }
                        LabeledContent("Service handle",
                                       value: hex(session.contextPseudonym("app:service")?.handle ?? Data()))
                            .font(.caption.monospaced())
                        LabeledContent("Message handle",
                                       value: hex(session.contextPseudonym("msg:peer")?.handle ?? Data()))
                            .font(.caption.monospaced())
                        Text("System-ID: never shown (anonymous root). Each context gets a distinct, uncorrelatable handle.")
                            .font(.caption2).foregroundStyle(.secondary)
                    }
                }

                // ABOUT + Beta note — the ONLY place the PoC disclaimer lives now.
                Section {
                    Button {
                        showAbout = true
                    } label: {
                        Label("About Atlas", systemImage: "info.circle")
                    }
                    Text("Beta — early preview")
                        .font(.caption2).foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Profile")
            .sheet(isPresented: $showAbout) { DisclaimerView(inSheet: true) }
        }
    }
}
