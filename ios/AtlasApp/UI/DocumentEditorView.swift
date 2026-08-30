import SwiftUI
import UIKit

/// Block editor for a provenanced document — write text, add links, drop in images/videos
/// from your vault. On save it's sealed + attested (verified-human authorship); editing an
/// existing doc overwrites in place and re-attests. External services would be link blocks,
/// never live web embeds.
struct DocumentEditorView: View {
    @EnvironmentObject var session: AtlasSession
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var space: AppSpace
    let existingVaultName: String?          // nil = new document

    @State private var title = "Untitled"
    @State private var bodyText = ""
    @State private var vaultName: String?
    @State private var busy = false
    @State private var err: String?
    @State private var loaded = false
    @State private var pdfURL: URL?
    @State private var showShare = false

    /// Author is NOT a field — it is the current persona's signing identity, shown read-only.
    private var authorLabel: String {
        let uname = session.username.trimmingCharacters(in: .whitespaces)
        return uname.isEmpty ? "this persona" : uname
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Title", text: $title).font(.title2.bold())
                    LabeledContent("Author") {
                        HStack(spacing: 6) {
                            if session.isCurrentProfileVerified {
                                Image(systemName: "checkmark.seal.fill").foregroundStyle(.blue)
                            }
                            Text(authorLabel).foregroundStyle(.secondary)
                        }
                    }
                }
                Section {
                    TextEditor(text: $bodyText).frame(minHeight: 340)
                } header: {
                    Text("Document")
                } footer: {
                    Text("Signed as “\(authorLabel)” and provenanced on save — authorship is bound to your verified identity, not typed.")
                }
                Section {
                    Button {
                        pdfURL = session.exportProvenancedPDF(title: title, body: bodyText)
                        showShare = pdfURL != nil
                    } label: {
                        Label("Export as provenanced PDF", systemImage: "doc.badge.arrow.up")
                    }
                    .disabled(bodyText.trimmingCharacters(in: .whitespaces).isEmpty)
                } footer: {
                    Text("A PDF stamped on every page with your author name, did:cid, the content hash, and your signature — anyone can recompute the hash and verify who made it, unaltered.")
                }
            }
            .navigationTitle(vaultName == nil ? "New document" : "Edit")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .primaryAction) {
                    Button(busy ? "Saving…" : "Save") { save() }.disabled(busy).bold()
                }
            }
            .alert("Save failed", isPresented: Binding(get: { err != nil }, set: { if !$0 { err = nil } })) {
                Button("OK") { err = nil }
            } message: { Text(err ?? "") }
            .sheet(isPresented: $showShare) { if let pdfURL { ActivityShareSheet(items: [pdfURL]) } }
            .task { await loadIfNeeded() }
        }
    }

    private func loadIfNeeded() async {
        guard !loaded else { return }
        loaded = true
        if let vn = existingVaultName {
            vaultName = vn
            if let d = await session.vaultOpenFile(vn), let parsed = AtlasDocument.decode(d) {
                title = parsed.title
                bodyText = parsed.blocks.filter { $0.type == .text }.map { $0.text }.joined(separator: "\n\n")
            }
        }
    }

    private func save() {
        Task {
            busy = true
            let base = title.trimmingCharacters(in: .whitespaces).isEmpty ? "Untitled" : title
            var doc = AtlasDocument.empty(title: base)
            var blk = DocBlock(type: .text)
            blk.text = bodyText
            doc.blocks = [blk]
            let data = doc.encoded()
            if let vn = vaultName {
                err = await session.updateVaultFile(vn, data: data)
            } else {
                err = await session.captureSave(name: "\(base).atlasdoc", data: data, kind: "doc", to: space)
                if err == nil { vaultName = space.items.last?.vaultName }
            }
            busy = false
            if err == nil { dismiss() }
        }
    }
}

/// Inline image loaded from the vault under live presence.
struct AsyncVaultImage: View {
    @EnvironmentObject var session: AtlasSession
    let name: String
    @State private var img: UIImage?

    var body: some View {
        Group {
            if let img {
                Image(uiImage: img).resizable().scaledToFit().clipShape(RoundedRectangle(cornerRadius: 8))
            } else {
                RoundedRectangle(cornerRadius: 8).fill(Color(.secondarySystemBackground))
                    .frame(height: 120).overlay(ProgressView())
            }
        }
        .task { if img == nil, let d = await session.vaultOpenFile(name), let u = UIImage(data: d) { img = u } }
    }
}

/// Pick an existing vault item of a given kind (image/video) to place in a document.
struct VaultItemPicker: View {
    @EnvironmentObject var session: AtlasSession
    @Environment(\.dismiss) private var dismiss
    let kind: String
    var onPick: (String) -> Void

    var body: some View {
        NavigationStack {
            List(session.vaultFiles.filter { $0.kind == kind }) { f in
                Button { onPick(f.name); dismiss() } label: {
                    Label(f.name, systemImage: kind == "image" ? "photo" : "film")
                }
            }
            .navigationTitle("Choose \(kind)")
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } } }
            .overlay {
                if session.vaultFiles.filter({ $0.kind == kind }).isEmpty {
                    ContentUnavailableView("No \(kind)s", systemImage: kind == "image" ? "photo" : "film",
                                           description: Text("Capture one first."))
                }
            }
        }
    }
}

extension DocBlock.BlockType: Identifiable { var id: String { rawValue } }

/// Drives a `.sheet(item:)` to open the document editor (new when `vaultName == nil`).
struct DocEditTarget: Identifiable {
    let id = UUID()
    let space: AppSpace
    let vaultName: String?
}
