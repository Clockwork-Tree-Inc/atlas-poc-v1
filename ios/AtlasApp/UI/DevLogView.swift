import SwiftUI
import UIKit

/// Developer log — the PERSISTED, exportable behaviour trace (survives relaunch, unlike the RAM-only
/// live feed). Filter by level, search text, share the full file off-device, or clear it. Records the
/// same event lines the app surfaces + fatal-crash markers — never keys, plaintext, or raw signals.
struct DevLogView: View {
    @State private var lines: [String] = []
    @State private var query = ""
    @State private var level = "ALL"
    @State private var exportURL: URL?
    @State private var showShare = false

    private let levels = ["ALL", "ERR", "WRN", "INF", "DBG"]

    private var filtered: [String] {
        lines.filter { l in
            (level == "ALL" || l.contains("[\(level)]"))
            && (query.isEmpty || l.localizedCaseInsensitiveContains(query))
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            Picker("Level", selection: $level) {
                ForEach(levels, id: \.self) { Text($0).tag($0) }
            }
            .pickerStyle(.segmented)
            .padding(.horizontal).padding(.top, 8)

            if filtered.isEmpty {
                ContentUnavailableView("No log lines",
                                       systemImage: "doc.text.magnifyingglass",
                                       description: Text("Use the app for a bit, then pull to refresh."))
                    .frame(maxHeight: .infinity)
            } else {
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 2) {
                            ForEach(Array(filtered.enumerated()), id: \.offset) { i, l in
                                Text(l)
                                    .font(.system(.caption2, design: .monospaced))
                                    .foregroundStyle(color(for: l))
                                    .textSelection(.enabled)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .id(i)
                            }
                        }
                        .padding(.horizontal, 10).padding(.vertical, 8)
                    }
                    .onAppear { if let last = filtered.indices.last { proxy.scrollTo(last, anchor: .bottom) } }
                }
            }
        }
        .navigationTitle("Developer log")
        .navigationBarTitleDisplayMode(.inline)
        .searchable(text: $query, prompt: "Search log")
        .toolbar {
            ToolbarItemGroup(placement: .topBarTrailing) {
                Button { reload() } label: { Image(systemName: "arrow.clockwise") }
                Button { if let u = DevLog.shared.exportURL() { exportURL = u; showShare = true } }
                    label: { Image(systemName: "square.and.arrow.up") }
                Menu {
                    Button("Clear log", role: .destructive) { DevLog.shared.clear(); reload() }
                } label: { Image(systemName: "ellipsis.circle") }
            }
        }
        .sheet(isPresented: $showShare) {
            if let exportURL { ShareSheet(items: [exportURL]) }
        }
        .onAppear(perform: reload)
        .refreshable { reload() }
    }

    private func reload() { lines = DevLog.shared.tail() }

    private func color(for line: String) -> Color {
        if line.contains("[ERR]") || line.contains("CRASH") { return .red }
        if line.contains("[WRN]") { return .orange }
        if line.contains("[DBG]") { return .secondary }
        return .primary
    }
}

/// UIKit share sheet bridge (SwiftUI ShareLink needs a Transferable; a file URL via UIActivity is
/// simplest and works for exporting the log file).
private struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }
    func updateUIViewController(_ vc: UIActivityViewController, context: Context) {}
}
