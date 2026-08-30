import SwiftUI
import AVKit
import PDFKit
import AtlasCore

/// Provenanced content viewer — renders ANY vault item (image / video / audio / PDF / text) and
/// surfaces its verified-human provenance badge + a sybil-resistant view count. ONE viewer for all
/// content types (the "one substrate, many shapes" invariant): media and documents are the same.
///
/// The bytes are decrypted under live presence, then verified against their provenance bundle (a
/// stored verdict would be meaningless — the bytes are what prove it). Rendering uses the system
/// viewers here for the PoC; the media-decode ISOLATION constraint (memory-safe decode, sandboxed,
/// no reach to secrets) is a Phase-F hardening item, tracked in PLATFORM_PLAN.md §7.3.
struct ContentViewerView: View {
    @EnvironmentObject var session: AtlasSession
    let file: AtlasSession.VaultFile

    @State private var data: Data?
    @State private var verdict: ProvenanceVerdict?
    @State private var views = 0
    @State private var loading = true
    @State private var errorMsg: String?

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                badge
                content
            }
            .padding()
        }
        .navigationTitle(file.name)
        .navigationBarTitleDisplayMode(.inline)
        .task { await load() }
        .alert("Viewer", isPresented: Binding(get: { errorMsg != nil }, set: { if !$0 { errorMsg = nil } })) {
            Button("OK") { errorMsg = nil }
        } message: { Text(errorMsg ?? "") }
    }

    // MARK: provenance badge + view count

    @ViewBuilder private var badge: some View {
        VStack(spacing: 8) {
            HStack(spacing: 10) {
                if let v = verdict {
                    Image(systemName: v.accountable ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                        .font(.title2).foregroundStyle(v.accountable ? .green : .orange)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(v.accountable ? "Authored by a verified human" : "Provenance incomplete")
                            .font(.subheadline).bold()
                        Text(v.accountable
                             ? "Signed · live · anchored — these exact bytes, provably."
                             : (v.reasons.first ?? "one or more checks failed"))
                            .font(.caption).foregroundStyle(.secondary)
                    }
                } else {
                    Image(systemName: "questionmark.circle").font(.title2).foregroundStyle(.secondary)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Stored — origin not attested").font(.subheadline).bold()
                        Text("Imported into your vault; no verified-human authorship claim.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                Spacer()
            }
            HStack {
                Label("\(views) verified view\(views == 1 ? "" : "s")", systemImage: "eye")
                    .font(.caption2).foregroundStyle(.secondary)
                Spacer()
                Text("distinct verified humans · no identities stored")
                    .font(.caption2).foregroundStyle(.tertiary)
            }
        }
        .padding()
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 12))
    }

    // MARK: content render (by kind)

    @ViewBuilder private var content: some View {
        if loading {
            ProgressView("opening under live presence…").padding(40)
        } else if let data {
            switch file.kind {
            case "image":
                if let img = UIImage(data: data) {
                    Image(uiImage: img).resizable().scaledToFit()
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                } else { unsupported }
            case "pdf":
                PDFKitView(data: data).frame(minHeight: 500)
            case "video", "audio":
                PlayerView(data: data, ext: (file.name as NSString).pathExtension)
            case "text":
                Text(String(data: data, encoding: .utf8) ?? "(not UTF-8 text)")
                    .font(.system(.footnote, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
            default:
                unsupported
            }
        }
    }

    private var unsupported: some View {
        ContentUnavailableView("Can't preview this type", systemImage: "doc",
            description: Text("\(byteStr(file.size)) · sealed in your vault."))
    }

    // MARK: load

    private func load() async {
        loading = true; defer { loading = false }
        guard let d = await session.vaultOpenFile(file.name) else {
            errorMsg = "No live pulse — wear your ring so the vault unlocks."
            return
        }
        data = d
        verdict = session.provenanceVerdict(for: file.name, content: d)
        views = session.registerView(of: file.name)
    }

    private func byteStr(_ n: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(n), countStyle: .file)
    }
}

/// AVPlayer needs a file URL; write the decrypted bytes to a temp file for playback.
private struct PlayerView: View {
    let data: Data
    let ext: String
    @State private var url: URL?

    var body: some View {
        Group {
            if let url {
                VideoPlayer(player: AVPlayer(url: url)).frame(height: 300)
            } else {
                ProgressView()
            }
        }
        .onAppear {
            let u = FileManager.default.temporaryDirectory
                .appendingPathComponent("view.\(ext.isEmpty ? "mov" : ext)")
            try? data.write(to: u)
            url = u
        }
    }
}

private struct PDFKitView: UIViewRepresentable {
    let data: Data
    func makeUIView(context: Context) -> PDFView {
        let v = PDFView()
        v.autoScales = true
        v.document = PDFDocument(data: data)
        return v
    }
    func updateUIView(_ v: PDFView, context: Context) {
        if v.document == nil { v.document = PDFDocument(data: data) }
    }
}
