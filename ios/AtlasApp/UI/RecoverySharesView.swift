import SwiftUI
import AtlasCore
import UniformTypeIdentifiers

/// Recovery shards — the seed split 2-of-n at enrol. Phone shard stays sealed in the SE; export the
/// USB shard to a stick, hand the CONTACT shard to a trusted person (an opaque blob — they can't
/// tell whose it is or what it recovers), and optionally park the SERVER shard on your node
/// (useless without one of YOUR shards — no all-institutional quorum can ever reconstruct).
/// ANY TWO shards rebuild your identity on a new phone.
struct RecoverySharesView: View {
    @EnvironmentObject var session: AtlasSession
    @State private var exported: [String: URL] = [:]

    private func describe(_ label: String) -> (String, String, String) {
        switch label {
        case "user:phone-se": return ("Your half · Phone (Secure Enclave)", "iphone",
                                      "Sealed in this phone's Secure Enclave. Lives here.")
        case "user:usb": return ("Your half · USB stick", "externaldrive.fill",
                                 "Export to a USB stick / Files, then remove it from the phone.")
        case "user:contact": return ("Your half · Trusted contact", "person.fill.badge.plus",
                                     "Hand to a trusted person — an opaque blob; silent, 100% secret.")
        case let l where l.hasPrefix("server:"):
            return ("Server half · \(l.replacingOccurrences(of: "server:", with: ""))", "server.rack",
                    "A server-half share. Useless without a threshold of YOUR half — the servers alone can never recover you.")
        default: return (label, "questionmark", "")
        }
    }

    var body: some View {
        List {
            Section {
                Text("Your identity seed is split into shards — any TWO rebuild it on a new phone; any ONE alone is mathematically nothing. Server-class shards can never combine to recover you.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("Shards") {
                if session.shardLabels.isEmpty {
                    Text("No shards on this phone — they were exported, or this identity predates the shard ceremony (re-enrol to create them).")
                        .font(.callout).foregroundStyle(.secondary)
                }
                ForEach(session.shardLabels, id: \.self) { label in
                    let d = describe(label)
                    VStack(alignment: .leading, spacing: 6) {
                        Label(d.0, systemImage: d.1).font(.headline)
                        Text(d.2).font(.caption).foregroundStyle(.secondary)
                        if label != "user:phone-se" {   // the phone-SE share stays sealed here
                            HStack {
                                if let url = exported[label] {
                                    ShareLink(item: url) { Label("Share shard file", systemImage: "square.and.arrow.up") }
                                        .font(.callout)
                                    Button(role: .destructive) { session.removeShard(label); exported[label] = nil } label: {
                                        Text("Remove from phone")
                                    }
                                    .font(.callout)
                                } else {
                                    Button { export(label) } label: {
                                        Label("Export (Face ID)", systemImage: "lock.open")
                                    }
                                    .font(.callout)
                                }
                            }
                        }
                    }
                    .padding(.vertical, 2)
                }
            }
            Section {
                Text("After exporting a shard, remove it from the phone — a shard is only a second factor once it lives somewhere else.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Recovery shards")
        .onAppear { session.loadShardLabels() }
    }

    private func export(_ label: String) {
        guard let data = session.exportShard(label) else { return }
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("atlas-shard-\(label).atlasshard")
        try? data.write(to: url)
        exported[label] = url
    }
}

/// Recover an identity on a new/wiped phone from ANY TWO shard files.
struct RecoverFromShardsView: View {
    @EnvironmentObject var session: AtlasSession
    @Environment(\.dismiss) private var dismiss
    @State private var shards: [Data] = []
    @State private var showImporter = false
    @State private var status = ""

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Text("Pick any TWO shard files (USB stick, a file a trusted contact returns, your server). Two shards rebuild your identity; one alone is nothing.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section("Shards loaded: \(shards.count)/2") {
                    Button { showImporter = true } label: {
                        Label("Add shard file", systemImage: "doc.badge.plus")
                    }
                    if shards.count >= 2 {
                        Button {
                            do { try session.recoverFromShards(shards); dismiss() }
                            catch { status = "Recovery failed: \(error)" }
                        } label: {
                            Label("Recover identity", systemImage: "person.crop.circle.badge.checkmark")
                                .font(.headline)
                        }
                    }
                    if !status.isEmpty { Text(status).font(.caption).foregroundStyle(.orange) }
                }
            }
            .navigationTitle("Recover from shards")
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } } }
            .fileImporter(isPresented: $showImporter, allowedContentTypes: [.data, .json],
                          allowsMultipleSelection: true) { result in
                if case .success(let urls) = result {
                    for url in urls {
                        let scoped = url.startAccessingSecurityScopedResource()
                        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                        if let d = try? Data(contentsOf: url) { shards.append(d) }
                    }
                }
            }
        }
    }
}
