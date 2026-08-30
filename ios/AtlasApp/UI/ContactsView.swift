import SwiftUI
import AtlasCore

/// A saved contact. Barebones: name + the connect code they shared. (Verified person_tag / caller-ID
/// binding arrives when the relay redemption + NFC share are wired — see Contact.swift in AtlasCore.)
struct SavedContact: Identifiable, Codable {
    let id: UUID
    let name: String
    let code: String
}

/// Per-persona contacts, persisted locally. NOTE (barebones): stored in UserDefaults keyed by the
/// persona handle for now — isolated per persona, but NOT vault-sealed yet; sealing into the
/// per-persona vault (like the space graph) is the hardening follow-up.
final class ContactsStore: ObservableObject {
    @Published var contacts: [SavedContact] = []
    @Published var myCode: String = ""
    private let contactsKey: String
    private let codeKey: String

    init(personaKey: String) {
        contactsKey = "atlas.contacts.\(personaKey)"
        codeKey = "atlas.mycode.\(personaKey)"
        if let data = UserDefaults.standard.data(forKey: contactsKey),
           let c = try? JSONDecoder().decode([SavedContact].self, from: data) { contacts = c }
        if let m = UserDefaults.standard.string(forKey: codeKey), !m.isEmpty { myCode = m }
        else { myCode = Self.genCode(); UserDefaults.standard.set(myCode, forKey: codeKey) }
    }

    private func save() {
        if let d = try? JSONEncoder().encode(contacts) { UserDefaults.standard.set(d, forKey: contactsKey) }
    }

    func add(name: String, code: String) {
        contacts.append(SavedContact(id: UUID(), name: name, code: code)); save()
    }

    func remove(at offsets: IndexSet) { contacts.remove(atOffsets: offsets); save() }

    /// A short, human-typeable connect code (base32, window-unique on the relay in production).
    static func genCode() -> String {
        Primitives.randomBytes(5).map { String(format: "%02X", $0) }.joined()
    }
}

/// CONTACTS — add people and share your own contact. Backend (connect codes / caller-ID /
/// reachability) is in AtlasCore's Contact.swift; this surfaces add + share now, with NFC tap and
/// relay redemption to follow.
struct ContactsScreen: View {
    @EnvironmentObject var session: AtlasSession
    var body: some View {
        NavigationStack {
            if let p = session.currentPersona {
                ContactsList(personaKey: p.handle.map { String(format: "%02x", $0) }.joined(),
                             displayName: p.username)
                    .id(p.handle)   // rebuild per persona → isolation
            } else {
                ContentUnavailableView("No profile selected",
                                       systemImage: "person.crop.circle.badge.questionmark",
                                       description: Text("Pick a profile on Home."))
            }
        }
    }
}

private struct ContactsList: View {
    let personaKey: String
    let displayName: String
    @EnvironmentObject var session: AtlasSession
    @StateObject private var store: ContactsStore
    @State private var showAdd = false
    @State private var chatWith: AppSpace?

    init(personaKey: String, displayName: String) {
        self.personaKey = personaKey
        self.displayName = displayName
        _store = StateObject(wrappedValue: ContactsStore(personaKey: personaKey))
    }

    var body: some View {
        List {
            Section {
                HStack(spacing: 12) {
                    Image(systemName: "qrcode").font(.title2).foregroundStyle(.tint)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(displayName.isEmpty ? "You" : displayName).font(.headline)
                        Text("connect code: \(store.myCode)").font(.caption.monospaced()).foregroundStyle(.secondary)
                    }
                    Spacer()
                    ShareLink(item: "Add me on Atlas — connect code: \(store.myCode)") {
                        Image(systemName: "square.and.arrow.up").font(.title3)
                    }
                }
            } header: {
                Text("Your contact")
            } footer: {
                Text("Share your connect code — a contact adds you by entering it. Tap-to-share (NFC) and spoof-proof relay redemption arrive with the network.")
            }

            Section("Contacts") {
                if store.contacts.isEmpty {
                    Text("No contacts yet — tap + to add one.").font(.callout).foregroundStyle(.secondary)
                }
                ForEach(store.contacts) { c in
                    HStack(spacing: 12) {
                        Image(systemName: "person.crop.circle.fill").font(.title2).foregroundStyle(.tint)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(c.name).font(.headline)
                            Text(c.code.isEmpty ? "no code" : c.code).font(.caption.monospaced()).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button { chatWith = session.startChat(with: c.name) } label: {
                            Image(systemName: "message.fill").foregroundStyle(.tint)
                        }
                        .buttonStyle(.plain)
                    }
                    .contextMenu {
                        Button { chatWith = session.startChat(with: c.name) } label: {
                            Label("Message", systemImage: "message")
                        }
                        // Add this person into a space's member context (folders at the root).
                        if let root = session.currentRoot {
                            Menu {
                                ForEach(root.children.filter { $0.kind != .chat }) { sp in
                                    Button(sp.name) {
                                        if !sp.members.contains(c.name) {
                                            sp.members.append(c.name)
                                            session.persistGraph()
                                        }
                                    }
                                }
                            } label: { Label("Add to space…", systemImage: "square.stack.3d.up") }
                        }
                    }
                }
                .onDelete { store.remove(at: $0) }
            }
        }
        .navigationTitle("Contacts")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button { showAdd = true } label: { Image(systemName: "person.badge.plus") }
            }
        }
        .sheet(isPresented: $showAdd) {
            AddContactSheet { name, code in store.add(name: name, code: code) }
        }
        .sheet(item: $chatWith) { chat in
            NavigationStack { MessagingView(chat: chat) }.environmentObject(session)
        }
    }
}

private struct AddContactSheet: View {
    var onAdd: (String, String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var code = ""

    var body: some View {
        NavigationStack {
            Form {
                Section("New contact") {
                    TextField("Name", text: $name)
                    TextField("Connect code", text: $code)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                }
                Section {
                    Text("Enter their name and the connect code they shared. Scanning by NFC / QR and spoof-proof relay redemption arrive with the network.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Add contact")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Add") {
                        let n = name.trimmingCharacters(in: .whitespaces)
                        guard !n.isEmpty else { return }
                        onAdd(n, code.trimmingCharacters(in: .whitespaces)); dismiss()
                    }
                    .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
        }
    }
}
