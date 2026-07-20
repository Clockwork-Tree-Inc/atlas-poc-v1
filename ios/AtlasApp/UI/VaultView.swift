import SwiftUI
import PhotosUI
import UniformTypeIdentifiers
import AtlasCore

/// The Vault — a real file browser over the AtlasCore secure vault. Add files from
/// the Files app or your photo library; each is sealed to a storage key that never
/// leaves the (model) Enclave, released ONLY under live presence (your ring pulse +
/// biometric). Browse them, tap to open (decrypt-on-demand under presence), swipe to
/// delete. Opaque at rest; no live pulse -> the gate stays closed.
struct VaultView: View {
    @EnvironmentObject var session: AtlasSession
    @State private var showFileImporter = false
    @State private var photoItems: [PhotosPickerItem] = []
    @State private var busy = false
    @State private var errorMsg: String?

    var body: some View {
        NavigationStack {
            Group {
                if session.vault == nil {
                    ContentUnavailableView("Vault locked", systemImage: "lock.doc",
                        description: Text("Finish setup to open your vault."))
                } else if session.vaultFiles.isEmpty {
                    ContentUnavailableView {
                        Label("Your vault is empty", systemImage: "lock.doc")
                    } description: {
                        Text("Add a file or photo — each one is sealed under your live presence.")
                    } actions: {
                        addMenu.buttonStyle(.borderedProminent)
                    }
                } else {
                    fileList
                }
            }
            .navigationTitle("Vault")
            .toolbar { if session.vault != nil { ToolbarItem(placement: .primaryAction) { addMenu } } }
            .fileImporter(isPresented: $showFileImporter,
                          allowedContentTypes: [.item], allowsMultipleSelection: true) { result in
                if case .success(let urls) = result { Task { await importFiles(urls) } }
            }
            .onChange(of: photoItems) { _, items in
                if !items.isEmpty { Task { await importPhotos(items); photoItems = [] } }
            }
            .overlay {
                if busy {
                    ProgressView("under live presence…").padding(20)
                        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 12))
                }
            }
            .alert("Vault", isPresented: Binding(get: { errorMsg != nil }, set: { if !$0 { errorMsg = nil } })) {
                Button("OK") { errorMsg = nil }
            } message: { Text(errorMsg ?? "") }
        }
    }

    private var addMenu: some View {
        Menu {
            Button { showFileImporter = true } label: { Label("Add from Files", systemImage: "folder") }
            PhotosPicker(selection: $photoItems, maxSelectionCount: 10, matching: .images) {
                Label("Add Photos", systemImage: "photo")
            }
        } label: { Image(systemName: "plus") }
    }

    private var fileList: some View {
        List {
            Section {
                ForEach(session.vaultFiles) { f in
                    NavigationLink { ContentViewerView(file: f) } label: { row(f) }
                }
                .onDelete { idx in idx.map { session.vaultFiles[$0].name }.forEach(session.vaultDeleteFile) }
            } header: {
                Label("\(session.vaultFiles.count) file\(session.vaultFiles.count == 1 ? "" : "s") · sealed at rest, opened only under your live pulse",
                      systemImage: "checkmark.seal")
            }
        }
    }

    private func row(_ f: AtlasSession.VaultFile) -> some View {
        HStack(spacing: 12) {
            Image(systemName: icon(f.kind)).font(.title3).frame(width: 30).foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 2) {
                Text(f.name).foregroundStyle(.primary).lineLimit(1)
                Text("\(byteStr(f.size)) · \(f.addedAt.formatted(date: .abbreviated, time: .shortened))")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Image(systemName: "lock.fill").font(.caption2).foregroundStyle(.secondary)
        }
    }

    // MARK: actions

    private func importFiles(_ urls: [URL]) async {
        busy = true; defer { busy = false }
        for url in urls {
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            guard let data = try? Data(contentsOf: url) else { continue }
            if let err = await session.vaultAddFile(name: url.lastPathComponent, data: data,
                                                    kind: kind(forExtension: url.pathExtension)) {
                errorMsg = err; break
            }
        }
    }

    private func importPhotos(_ items: [PhotosPickerItem]) async {
        busy = true; defer { busy = false }
        var i = session.vaultFiles.count + 1
        for item in items {
            guard let data = try? await item.loadTransferable(type: Data.self) else { continue }
            if let err = await session.vaultAddFile(name: "photo-\(i).jpg", data: data, kind: "image") {
                errorMsg = err; break
            }
            i += 1
        }
    }

    // MARK: helpers

    private func kind(forExtension ext: String) -> String {
        switch ext.lowercased() {
        case "jpg", "jpeg", "png", "heic", "heif", "gif", "webp": return "image"
        case "mp4", "mov", "m4v": return "video"
        case "mp3", "m4a", "wav", "aac", "aiff", "caf": return "audio"
        case "pdf": return "pdf"
        case "txt", "md", "csv", "json", "log", "rtf": return "text"
        default: return "file"
        }
    }

    private func icon(_ kind: String) -> String {
        switch kind {
        case "image": return "photo"
        case "video": return "film"
        case "audio": return "waveform"
        case "pdf": return "doc.richtext"
        case "text": return "doc.text"
        default: return "doc"
        }
    }

    private func byteStr(_ n: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(n), countStyle: .file)
    }
}
