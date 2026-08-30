import SwiftUI
import AtlasCore

/// Your persona's SPACE ("land") — host anything digital (a note, a file, a page — all just bytes),
/// committed and owner-gated, and ISOLATED per persona: switch persona and this becomes a different
/// space. This is the "host anything digital" surface. The commitment lives here; the bytes seal
/// into your vault (app-layer follow-on). Serving hosted bytes to others is the storage long-pole.
struct SpacesView: View {
    @EnvironmentObject var session: AtlasSession
    @State private var draft = ""

    var body: some View {
        NavigationStack {
            Group {
                if session.land == nil {
                    ContentUnavailableView("No space yet", systemImage: "square.stack.3d.up",
                        description: Text("Finish setup to open your persona's space."))
                } else {
                    list
                }
            }
            .navigationTitle("Space")
            .safeAreaInset(edge: .bottom) { if session.land != nil { composer } }
        }
    }

    private var list: some View {
        List {
            Section {
                if session.hostedItems.isEmpty {
                    Text("Nothing hosted yet — post a note or host content below.")
                        .foregroundStyle(.secondary).font(.callout)
                } else {
                    ForEach(session.hostedItems, id: \.contentHash) { item in
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(hex(item.contentHash, 12))
                                    .font(.system(.body, design: .monospaced)).lineLimit(1)
                                Text("#\(item.seq) · committed").font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            let s = session.score(for: item.contentHash)
                            Button { session.vote(on: item.contentHash, up: true) } label: {
                                Image(systemName: "hand.thumbsup")
                            }.buttonStyle(.borderless)
                            Text("\(s.net)").monospacedDigit().frame(minWidth: 22)
                            Button { session.vote(on: item.contentHash, up: false) } label: {
                                Image(systemName: "hand.thumbsdown")
                            }.buttonStyle(.borderless)
                        }
                    }
                }
            } header: {
                Label("persona \(session.currentPersona.map { hex($0.handle, 6) } ?? "—") · \(session.hostedItems.count) hosted",
                      systemImage: "person.crop.square")
            } footer: {
                Text("Isolated per persona: switch persona and this space changes. Content is committed here; the bytes seal into your vault.")
            }
        }
    }

    private var composer: some View {
        HStack(spacing: 8) {
            TextField("Host a note or content…", text: $draft, axis: .vertical)
                .textFieldStyle(.roundedBorder)
            Button {
                let d = draft.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !d.isEmpty else { return }
                session.hostToLand(Data(d.utf8)); draft = ""
            } label: { Image(systemName: "square.and.arrow.up.on.square").font(.title3) }
            .disabled(draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }
        .padding(8).background(.ultraThinMaterial)
    }

    private func hex(_ d: Data, _ n: Int) -> String {
        d.prefix(n).map { String(format: "%02x", $0) }.joined()
    }
}
