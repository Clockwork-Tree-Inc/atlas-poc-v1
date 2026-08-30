import SwiftUI
import AtlasCore

/// Self-service public profile for the ACTIVE persona (the anonymous -> public -> verified
/// spectrum). Anonymous by default; going public exposes ONLY what you type here — per persona,
/// unlinkable to your other personas. "Verified" is derived from authority attestations
/// (participant model) and appears once credential authorities are reachable via the node.
struct PublicProfileEditor: View {
    let personaKey: String
    let username: String
    @State private var isPublic = false
    @State private var displayName = ""
    @State private var bio = ""

    private var visKey: String { "atlas.profile.public.\(personaKey)" }
    private var nameKey: String { "atlas.profile.name.\(personaKey)" }
    private var bioKey: String { "atlas.profile.bio.\(personaKey)" }

    var body: some View {
        Form {
            Section {
                Toggle("Public profile", isOn: $isPublic)
            } footer: {
                Text(isPublic
                     ? "Discoverable under this persona only — your other personas stay unlinkable."
                     : "Anonymous (default): nothing about this persona is published.")
            }
            if isPublic {
                Section("What the world sees") {
                    TextField("Display name", text: $displayName)
                    TextField("Bio", text: $bio, axis: .vertical)
                }
                Section("Verification") {
                    Label("Not verified — no authority attestations yet", systemImage: "seal")
                        .font(.callout).foregroundStyle(.secondary)
                    Text("‘Verified by X ✓’ appears here once credential authorities (eID office, professional bodies) attest this persona. Trust binds to the authority's key, never a name.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .navigationTitle("Public profile")
        .onAppear {
            isPublic = UserDefaults.standard.bool(forKey: visKey)
            displayName = UserDefaults.standard.string(forKey: nameKey) ?? username
            bio = UserDefaults.standard.string(forKey: bioKey) ?? ""
        }
        .onChange(of: isPublic) { _, v in UserDefaults.standard.set(v, forKey: visKey) }
        .onChange(of: displayName) { _, v in UserDefaults.standard.set(v, forKey: nameKey) }
        .onChange(of: bio) { _, v in UserDefaults.standard.set(v, forKey: bioKey) }
    }
}
