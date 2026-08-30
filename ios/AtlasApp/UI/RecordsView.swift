import SwiftUI
import UIKit
import PDFKit
import UniformTypeIdentifiers
import AtlasCore

/// Sensitive records — the app surface for records assembly. Create a sealed record by typing text
/// OR importing any file (PDF, image, document — including a provenanced PDF you exported); open your
/// own under role + records checks; every open is written to a tamper-evident, symmetric access log.
struct RecordsView: View {
    @EnvironmentObject var session: AtlasSession
    @State private var showNew = false

    var body: some View {
        List {
            Section {
                Text("A sensitive record is a space at the high-protection tier: sealed at rest, opened only under your role, and every access — including your own — is written to a hash-chained log you can verify.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("Your records") {
                if session.sensitiveRecords.isEmpty {
                    Text("None yet — tap + to seal one (type it, or import a file).").font(.callout).foregroundStyle(.secondary)
                }
                ForEach(session.sensitiveRecords) { r in
                    NavigationLink { RecordDetailView(entry: r) } label: {
                        HStack {
                            Image(systemName: icon(r.kind)).foregroundStyle(.orange)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(r.title)
                                Text("\(r.kind) · sealed · \(r.space.log.entries.count) log entr\(r.space.log.entries.count == 1 ? "y" : "ies")")
                                    .font(.caption2).foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
        }
        .navigationTitle("Records")
        .toolbar { ToolbarItem(placement: .primaryAction) { Button { showNew = true } label: { Image(systemName: "plus") } } }
        .sheet(isPresented: $showNew) { NewRecordSheet().environmentObject(session) }
    }

    private func icon(_ kind: String) -> String {
        switch kind { case "pdf": return "doc.richtext.fill"; case "image": return "photo.fill"
        case "text": return "doc.text.fill"; default: return "lock.doc.fill" }
    }
}

private struct NewRecordSheet: View {
    @EnvironmentObject var session: AtlasSession
    @Environment(\.dismiss) private var dismiss
    @State private var title = ""
    @State private var content = ""
    @State private var showImporter = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Title") { TextField("e.g. Bloodwork 2026", text: $title) }
                Section("Type it") { TextEditor(text: $content).frame(minHeight: 180) }
                Section {
                    Button {
                        showImporter = true
                    } label: { Label("Import a file (PDF, image, document)", systemImage: "square.and.arrow.down") }
                } footer: {
                    Text("Seal an existing file — including a provenanced PDF you exported. It's encrypted under a fresh key; you become the sole governor.")
                }
            }
            .navigationTitle("New sensitive record")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .primaryAction) {
                    Button("Seal text") {
                        session.createSensitiveRecord(title: title.isEmpty ? "Untitled record" : title, content: content)
                        dismiss()
                    }.disabled(content.trimmingCharacters(in: .whitespaces).isEmpty).bold()
                }
            }
            .sheet(isPresented: $showImporter) {
                DocPicker { url in
                    let ok = url.startAccessingSecurityScopedResource()
                    defer { if ok { url.stopAccessingSecurityScopedResource() } }
                    guard let data = try? Data(contentsOf: url) else { return }
                    let name = title.isEmpty ? url.deletingPathExtension().lastPathComponent : title
                    session.createSensitiveRecord(title: name, data: data, kind: kind(for: url))
                    dismiss()
                }
            }
        }
    }

    private func kind(for url: URL) -> String {
        switch url.pathExtension.lowercased() {
        case "pdf": return "pdf"
        case "jpg", "jpeg", "png", "heic", "gif", "webp": return "image"
        case "txt", "md": return "text"
        default: return "file"
        }
    }
}

private struct RecordDetailView: View {
    @EnvironmentObject var session: AtlasSession
    let entry: AtlasSession.SensitiveRecordEntry
    @State private var openedData: Data?
    @State private var failed = false

    var body: some View {
        List {
            Section {
                if let d = openedData {
                    switch entry.kind {
                    case "pdf": PDFDataView(data: d).frame(minHeight: 420)
                    case "image":
                        if let img = UIImage(data: d) { Image(uiImage: img).resizable().scaledToFit() }
                        else { Text("Could not render image.") }
                    case "text": Text(String(decoding: d, as: UTF8.self)).textSelection(.enabled)
                    default: Text("Sealed file opened — \(d.count) bytes.").foregroundStyle(.secondary)
                    }
                } else {
                    Button {
                        if let d = session.openSensitiveRecordData(entry) { openedData = d; failed = false }
                        else { failed = true }
                    } label: { Label("Open (logged)", systemImage: "lock.open.fill") }
                    if failed { Text("Open refused — you lack the required role.").font(.caption).foregroundStyle(.orange) }
                }
            } header: {
                Text(entry.title)
            } footer: {
                Text("Opening writes an entry to the access log below — even your own opens are recorded, so the trail can't be argued with.")
            }
            Section("Access log") {
                if entry.space.log.entries.isEmpty {
                    Text("No accesses yet.").font(.caption).foregroundStyle(.secondary)
                }
                ForEach(Array(entry.space.log.entries.enumerated()), id: \.offset) { _, e in
                    HStack {
                        Image(systemName: e.notify ? "bell.badge.fill" : "checkmark.circle")
                            .foregroundStyle(e.notify ? .red : .secondary)
                        Text(e.action).font(.caption.monospaced())
                        Spacer()
                        Text("round \(e.round)").font(.caption2).foregroundStyle(.secondary)
                    }
                }
                if !entry.space.log.entries.isEmpty {
                    let ok = entry.space.log.verify()
                    Label(ok ? "Log intact (hash chain verifies)" : "LOG TAMPERED",
                          systemImage: ok ? "checkmark.shield.fill" : "xmark.shield.fill")
                        .font(.caption).foregroundStyle(ok ? .green : .red)
                }
            }
        }
        .navigationTitle("Record")
        .navigationBarTitleDisplayMode(.inline)
    }
}

/// PDFKit viewer for in-memory sealed PDF bytes.
private struct PDFDataView: UIViewRepresentable {
    let data: Data
    func makeUIView(context: Context) -> PDFView {
        let v = PDFView(); v.autoScales = true; v.document = PDFDocument(data: data); return v
    }
    func updateUIView(_ v: PDFView, context: Context) {
        if v.document == nil { v.document = PDFDocument(data: data) }
    }
}

/// Document picker for importing a file to seal.
private struct DocPicker: UIViewControllerRepresentable {
    let onPick: (URL) -> Void
    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let p = UIDocumentPickerViewController(forOpeningContentTypes: [.pdf, .image, .plainText, .item], asCopy: true)
        p.delegate = context.coordinator
        return p
    }
    func updateUIViewController(_ vc: UIDocumentPickerViewController, context: Context) {}
    func makeCoordinator() -> Coord { Coord(onPick: onPick) }
    final class Coord: NSObject, UIDocumentPickerDelegate {
        let onPick: (URL) -> Void
        init(onPick: @escaping (URL) -> Void) { self.onPick = onPick }
        func documentPicker(_ c: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
            if let u = urls.first { onPick(u) }
        }
    }
}
