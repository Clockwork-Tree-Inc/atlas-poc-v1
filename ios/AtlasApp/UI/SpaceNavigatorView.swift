import SwiftUI
import AtlasCore

/// (Legacy) profile picker — the Home tab now owns profile selection. Kept for reference;
/// not in the tab bar.
struct ProfilePickerView: View {
    @EnvironmentObject var session: AtlasSession
    @State private var path: [Data] = []
    @State private var newName = ""

    var body: some View {
        NavigationStack(path: $path) {
            List {
                ForEach(session.personas, id: \.handle) { p in
                    Button {
                        session.switchPersona(p); path = [p.handle]
                    } label: { Text(p.username.isEmpty ? "unnamed" : p.username) }
                }
            }
            .navigationTitle("Profiles")
            .navigationDestination(for: Data.self) { handle in
                if let p = session.personas.first(where: { $0.handle == handle }) {
                    SpaceNavigatorView(space: session.spaceRoot(for: p))
                } else {
                    Text("Profile unavailable").foregroundStyle(.secondary)
                }
            }
        }
    }
}

/// CASCADING SPACES. Render one `AppSpace` BY KIND, everything launchable from here:
///  • vault / folder → the container: child spaces + items, with a "+" that inserts ANYTHING
///    (new folder, new chat, camera/video/audio, files, an office doc) INTO this space, and
///    can set this folder as the default capture destination.
///  • chat  → the working chat (self-chat works immediately; add people/companies/AI).
///  • market→ ID-gated server market.
struct SpaceNavigatorView: View {
    @EnvironmentObject var session: AtlasSession
    @ObservedObject var space: AppSpace
    @State private var showCapture = false
    @State private var showFileImporter = false
    @State private var busy = false
    @State private var nameKind: SpaceKind?     // non-nil → show the name prompt for this kind
    @State private var newName = ""
    @State private var showAddPerson = false
    @State private var newPerson = ""
    @State private var ql: QuickLookTarget?
    @State private var editing: DocEditTarget?

    var body: some View {
        content
            .navigationTitle(space.name)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                if space.kind == .vault || space.kind == .folder {
                    ToolbarItem(placement: .primaryAction) { insertMenu }
                }
            }
            .sheet(isPresented: $showCapture) { CaptureSheet(space: space).environmentObject(session) }
            .sheet(item: $ql) { FileQuickLook(name: $0.name).environmentObject(session) }
            .sheet(item: $editing) { t in DocumentEditorView(space: t.space, existingVaultName: t.vaultName).environmentObject(session) }
            .fileImporter(isPresented: $showFileImporter, allowedContentTypes: [.item],
                          allowsMultipleSelection: true) { result in
                if case .success(let urls) = result { Task { await importFiles(urls) } }
            }
            .alert(nameKind == .chat ? "New chat" : "New folder",
                   isPresented: Binding(get: { nameKind != nil }, set: { if !$0 { nameKind = nil } })) {
                TextField(nameKind == .chat ? "Chat name" : "Folder name", text: $newName)
                Button("Create") { createNamed() }
                Button("Cancel", role: .cancel) { newName = ""; nameKind = nil }
            }
            .alert("Add person to this space", isPresented: $showAddPerson) {
                TextField("Name", text: $newPerson)
                Button("Add") {
                    let n = newPerson.trimmingCharacters(in: .whitespaces)
                    if !n.isEmpty, !space.members.contains(n) {
                        space.members.append(n)
                        session.persistGraph()
                    }
                    newPerson = ""
                }
                Button("Cancel", role: .cancel) { newPerson = "" }
            }
    }

    @ViewBuilder private var content: some View {
        switch space.kind {
        case .vault, .folder: cascade
        case .chat:           MessagingView(chat: space)
        case .market:         market
        }
    }

    // MARK: the "+" insert menu — launch anything into this space

    private var insertMenu: some View {
        Menu {
            Button { nameKind = .folder; newName = "" } label: { Label("New folder", systemImage: "folder.badge.plus") }
            Button { nameKind = .chat; newName = "" } label: { Label("New chat", systemImage: "plus.message") }
            Button { showAddPerson = true; newPerson = "" } label: { Label("Add person", systemImage: "person.badge.plus") }
            Divider()
            Button { showCapture = true } label: { Label("Camera · video · audio", systemImage: "camera.fill") }
            Button { showFileImporter = true } label: { Label("Add files", systemImage: "doc.badge.plus") }
            Button { editing = DocEditTarget(space: space, vaultName: nil) } label: { Label("New document", systemImage: "doc.text") }
            Divider()
            Menu {
                Button("Photos") { session.setDefaultCaptureFolder(space.id, for: "photo") }
                Button("Videos") { session.setDefaultCaptureFolder(space.id, for: "video") }
                Button("Audio") { session.setDefaultCaptureFolder(space.id, for: "audio") }
                Button("Documents") { session.setDefaultCaptureFolder(space.id, for: "document") }
                Divider()
                Button("Everything") { session.setDefaultCaptureFolder(space.id) }
            } label: {
                Label("Set as default capture folder for…", systemImage: "star")
            }
        } label: { Image(systemName: "plus") }
    }

    // MARK: container (child spaces + items)

    private var cascade: some View {
        List {
            Section {
                if space.children.isEmpty {
                    Text("No spaces").font(.callout).foregroundStyle(.secondary)
                }
                ForEach(space.children) { child in
                    NavigationLink(value: child) { spaceRow(child) }
                        .dropDestination(for: String.self) { names, _ in
                            for n in names {
                                if let it = space.items.first(where: { $0.vaultName == n }) {
                                    session.moveItem(it, to: child, from: space)
                                }
                            }
                            return true
                        }
                }
            } header: {
                Label("\(space.children.count) space\(space.children.count == 1 ? "" : "s")",
                      systemImage: "square.stack.3d.up.fill")
            }
            if !space.items.isEmpty {
                Section("Items (\(space.items.count))") {
                    ForEach(space.items) { item in itemRow(item) }
                }
            }
            if busy { Section { ProgressView("Saving…") } }
        }
    }

    private func spaceRow(_ child: AppSpace) -> some View {
        HStack(spacing: 12) {
            Image(systemName: child.kind.systemImage).font(.title3).frame(width: 30).foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 2) {
                Text(child.name).foregroundStyle(.primary)
                Text(subtitle(child)).font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private func subtitle(_ s: AppSpace) -> String {
        switch s.kind {
        case .chat:
            let n = s.members.count + 1
            return "chat · \(n) member\(n == 1 ? "" : "s")"
        default:
            return "\(s.kind.label) · \(s.children.count) space\(s.children.count == 1 ? "" : "s"), \(s.items.count) item\(s.items.count == 1 ? "" : "s")"
        }
    }

    @ViewBuilder private func itemRow(_ item: SpaceItem) -> some View {
        Group {
            if item.kind == "doc" {
                Button { editing = DocEditTarget(space: space, vaultName: item.vaultName) } label: {
                    Label(item.vaultName, systemImage: "doc.text.fill").foregroundStyle(.primary)
                }
            } else if let vf = session.vaultFiles.first(where: { $0.name == item.vaultName }) {
                NavigationLink { ContentViewerView(file: vf) } label: { Label(item.vaultName, systemImage: icon(item.kind)) }
            } else {
                Label(item.vaultName, systemImage: icon(item.kind)).foregroundStyle(.secondary)
            }
        }
        .draggable(item.vaultName)
        .contextMenu {
            Button { ql = QuickLookTarget(name: item.vaultName) } label: { Label("Preview", systemImage: "eye") }
            if let root = session.currentRoot {
                Menu {
                    ForEach(root.allFolders().filter { $0.id != space.id }) { f in
                        Button(f.name) { session.moveItem(item, to: f, from: space) }
                    }
                } label: { Label("Move to", systemImage: "folder") }
            }
        }
    }

    private func icon(_ kind: String) -> String {
        switch kind {
        case "image": return "photo"; case "video": return "film"; case "audio": return "waveform"
        case "pdf": return "doc.richtext"; case "text": return "doc.text"; default: return "doc"
        }
    }

    // MARK: market (ID-gated)

    @ViewBuilder private var market: some View {
        if session.isCurrentProfileVerified {
            ContentUnavailableView { Label("Market", systemImage: "cart.fill") } description: { Text("Listings pending.") }
        } else {
            VStack(spacing: 16) {
                Image(systemName: "lock.shield").font(.system(size: 44)).foregroundStyle(.orange)
                Text("Market — ID-verified profiles only").font(.headline).multilineTextAlignment(.center)
                Text("Government-ID verification (an on-device NFC scan of your ePassport / national eID) is being wired in; until it lands no profile is verified and the Market stays closed.")
                    .font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
            }
            .padding(32).frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    // MARK: actions

    private func createNamed() {
        guard let kind = nameKind else { return }
        let n = newName.trimmingCharacters(in: .whitespaces)
        session.createSpace(kind: kind, name: n.isEmpty ? kind.label : n, in: space)
        newName = ""; nameKind = nil
    }

    private func importFiles(_ urls: [URL]) async {
        busy = true; defer { busy = false }
        for url in urls {
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            guard let data = try? Data(contentsOf: url) else { continue }
            _ = await session.captureSave(name: url.lastPathComponent, data: data,
                                          kind: kindForExt(url.pathExtension), to: space, attested: false)
        }
    }

    private func kindForExt(_ ext: String) -> String {
        switch ext.lowercased() {
        case "jpg", "jpeg", "png", "heic", "heif", "gif", "webp": return "image"
        case "mp4", "mov", "m4v": return "video"
        case "mp3", "m4a", "wav", "aac", "aiff", "caf": return "audio"
        case "pdf": return "pdf"
        case "txt", "md", "csv", "json", "log", "rtf": return "text"
        default: return "file"
        }
    }
}

/// The capture sheet used by a space's "+": camera / video / audio straight into THIS space.
struct CaptureSheet: View {
    @EnvironmentObject var session: AtlasSession
    @ObservedObject var space: AppSpace
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                Text("Capture into “\(space.name)”").font(.headline).multilineTextAlignment(.center)
                CaptureControls(space: space)
                Spacer()
            }
            .padding()
            .navigationTitle("Capture")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Done") { dismiss() } } }
        }
    }
}
