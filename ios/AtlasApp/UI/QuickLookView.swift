import SwiftUI
import QuickLook

/// System QuickLook preview — renders PDF, Office docs (docx/xlsx/pptx), images, video, text,
/// etc. with no hand-rolled viewer. We decrypt the vault bytes to a temp file and hand the URL
/// to QLPreviewController.
struct QuickLookPreview: UIViewControllerRepresentable {
    let url: URL
    func makeUIViewController(context: Context) -> QLPreviewController {
        let c = QLPreviewController(); c.dataSource = context.coordinator; return c
    }
    func updateUIViewController(_ c: QLPreviewController, context: Context) { c.reloadData() }
    func makeCoordinator() -> Coordinator { Coordinator(url: url) }

    final class Coordinator: NSObject, QLPreviewControllerDataSource {
        let url: URL
        init(url: URL) { self.url = url }
        func numberOfPreviewItems(in c: QLPreviewController) -> Int { 1 }
        func previewController(_ c: QLPreviewController, previewItemAt i: Int) -> QLPreviewItem { url as NSURL }
    }
}

/// Opens a vault-sealed file by name: releases it under live presence, writes a temp copy,
/// and previews it with QuickLook.
struct FileQuickLook: View {
    @EnvironmentObject var session: AtlasSession
    let name: String
    @State private var url: URL?
    @State private var failed = false

    var body: some View {
        Group {
            if let url {
                QuickLookPreview(url: url).ignoresSafeArea()
            } else if failed {
                ContentUnavailableView("Couldn't open", systemImage: "exclamationmark.triangle",
                                       description: Text("The file couldn't be released from the vault."))
            } else {
                ProgressView("opening…")
            }
        }
        .task {
            if let u = await session.tempURL(for: name) { url = u } else { failed = true }
        }
    }
}

/// Identifiable wrapper so a name can drive a `.sheet(item:)`.
struct QuickLookTarget: Identifiable { let id = UUID(); let name: String }
