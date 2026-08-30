import SwiftUI
import AtlasCore

/// Claim a human-readable NAME (the persona's discoverable "domain") — unique, and provably yours
/// because the claim is signed by the persona's key. Others can then find this persona by the name;
/// personas you don't name stay undiscoverable (discoverability is opt-in, per persona).
struct NamingView: View {
    @EnvironmentObject var session: AtlasSession
    @State private var draft = ""
    @State private var showError = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    if let name = session.claimedName {
                        Label(name, systemImage: "checkmark.seal.fill").foregroundStyle(.tint)
                        Text("Others can find this persona at this name. It resolves to this persona only, and only you — holding its key — could have claimed it.")
                            .font(.caption).foregroundStyle(.secondary)
                    } else {
                        Text("Claim a human-readable name so others can find this persona. Unique across the registry, and provably yours.")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                } header: {
                    Label("persona \(session.currentPersona.map { hex($0.handle, 6) } ?? "—")",
                          systemImage: "person.crop.square")
                }
                Section {
                    TextField("e.g. yourname", text: $draft)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    Button("Claim name") {
                        if session.claimName(draft) { draft = "" } else { showError = true }
                    }
                    .disabled(draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || session.currentPersona == nil)
                } footer: {
                    Text("The name maps to this persona's opaque handle; it reveals nothing about you or your other personas.")
                }
            }
            .navigationTitle("Name")
            .alert("Couldn't claim that name", isPresented: $showError) {
                Button("OK") {}
            } message: { Text("It may already be taken, or setup isn't finished.") }
        }
    }

    private func hex(_ d: Data, _ n: Int) -> String {
        d.prefix(n).map { String(format: "%02x", $0) }.joined()
    }
}
