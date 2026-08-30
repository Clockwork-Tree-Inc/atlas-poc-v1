import SwiftUI
import AtlasCore

/// COMMS — one place for person-to-person communication: a CHAT tab (every chat across the
/// space graph + start a new one directly) and a CALLS tab (contacts + call log). WhatsApp/
/// Signal-style surface over the Atlas model: chats are spaces, members are contacts/agents.
struct CommsTabView: View {
    @EnvironmentObject var session: AtlasSession
    @State private var segment = 0

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                Picker("", selection: $segment) {
                    Text("Chats").tag(0)
                    Text("Calls").tag(1)
                }
                .pickerStyle(.segmented).padding(.horizontal).padding(.vertical, 6)
                if segment == 0 { ChatListView() } else { CallsView() }
            }
            .navigationTitle("Comms")
        }
        .id(session.currentPersona?.handle)   // per-persona isolation
    }
}

// MARK: - Chats (list + start-a-chat)

private struct ChatListView: View {
    @EnvironmentObject var session: AtlasSession
    @State private var showStart = false
    @State private var openChat: AppSpace?

    var body: some View {
        Group {
            if let root = session.currentRoot {
                let chats = root.allChats()
                if chats.isEmpty {
                    ContentUnavailableView {
                        Label("No chats", systemImage: "message")
                    } description: {
                        Text("Start one with + — pick a contact or name anyone.")
                    }
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
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button { showStart = true } label: { Image(systemName: "plus.message") }
            }
        }
        .sheet(isPresented: $showStart) {
            StartChatSheet { name in
                if let chat = session.startChat(with: name) { openChat = chat }
            }
            .environmentObject(session)
        }
        .navigationDestination(item: $openChat) { MessagingView(chat: $0) }
    }
}

/// Pick a contact (or type any name) to start a chat with.
private struct StartChatSheet: View {
    var onStart: (String) -> Void
    @EnvironmentObject var session: AtlasSession
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""

    private var contacts: [SavedContact] {
        guard let p = session.currentPersona else { return [] }
        return ContactsStore(personaKey: p.handle.map { String(format: "%02x", $0) }.joined()).contacts
    }

    var body: some View {
        NavigationStack {
            List {
                Section("Contacts") {
                    if contacts.isEmpty {
                        Text("No contacts yet — add them on the Contacts tab, or type a name below.")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                    ForEach(contacts) { c in
                        Button {
                            onStart(c.name); dismiss()
                        } label: {
                            Label(c.name, systemImage: "person.crop.circle.fill")
                        }
                    }
                }
                Section("Or name someone") {
                    HStack {
                        TextField("Name", text: $name)
                        Button("Start") {
                            let n = name.trimmingCharacters(in: .whitespaces)
                            guard !n.isEmpty else { return }
                            onStart(n); dismiss()
                        }
                        .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty)
                    }
                }
            }
            .navigationTitle("New chat")
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } } }
        }
    }
}

// MARK: - Calls (contacts + log; live audio rides the relay/node — honest scaffold)

private struct CallEntry: Identifiable, Codable {
    let id: UUID
    let name: String
    let at: Date
}

private struct CallsView: View {
    @EnvironmentObject var session: AtlasSession
    @State private var log: [CallEntry] = []
    @State private var calling: SavedContact?

    private var personaKey: String {
        session.currentPersona?.handle.map { String(format: "%02x", $0) }.joined() ?? "none"
    }
    private var contacts: [SavedContact] { ContactsStore(personaKey: personaKey).contacts }

    var body: some View {
        List {
            Section {
                Text("Voice/video rides your node's relay — calls connect once the network layer is up. Placing a call logs it and reserves the flow.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("Contacts") {
                if contacts.isEmpty {
                    Text("No contacts yet — add them on the Contacts tab.")
                        .font(.callout).foregroundStyle(.secondary)
                }
                ForEach(contacts) { c in
                    HStack {
                        Label(c.name, systemImage: "person.crop.circle.fill")
                        Spacer()
                        Button { place(c) } label: { Image(systemName: "phone.fill").foregroundStyle(.green) }
                    }
                }
            }
            Section("Recent") {
                if log.isEmpty { Text("No calls yet.").font(.callout).foregroundStyle(.secondary) }
                ForEach(log) { e in
                    HStack {
                        Image(systemName: "phone.arrow.up.right").foregroundStyle(.secondary)
                        Text(e.name)
                        Spacer()
                        Text(e.at, style: .time).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
        }
        .onAppear(perform: load)
        .sheet(item: $calling) { c in CallScreen(name: c.name) }
    }

    private func place(_ c: SavedContact) {
        log.insert(CallEntry(id: UUID(), name: c.name, at: Date()), at: 0)
        save()
        calling = c
    }

    private func load() {
        if let d = UserDefaults.standard.data(forKey: "atlas.calls.\(personaKey)"),
           let l = try? JSONDecoder().decode([CallEntry].self, from: d) { log = l }
    }
    private func save() {
        if let d = try? JSONEncoder().encode(log) {
            UserDefaults.standard.set(d, forKey: "atlas.calls.\(personaKey)")
        }
    }
}

private struct CallScreen: View {
    let name: String
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 24) {
            Spacer()
            Image(systemName: "person.crop.circle.fill").font(.system(size: 72)).foregroundStyle(.tint)
            Text(name).font(.title.bold())
            Text("Calling…").font(.callout).foregroundStyle(.secondary)
            Text("Audio connects over your node's relay — the network layer isn't up yet, so this call won't ring through.")
                .font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center)
                .padding(.horizontal, 40)
            Spacer()
            Button { dismiss() } label: {
                Image(systemName: "phone.down.fill").font(.title)
                    .padding(22).background(Circle().fill(.red)).foregroundStyle(.white)
            }
            .padding(.bottom, 40)
        }
    }
}
