import SwiftUI

/// Forward-secret group messaging over the LIVE session. The shared `AtlasSession`
/// owns the node relay + the private group LK. Until at least one other member is
/// online AND the group LK is co-derived, this shows a CONNECTION panel (node URL,
/// who you are, who the node sees, LK status, live log, Reconnect) so a stalled
/// bring-up is visible and fixable instead of a dead "waiting…" screen.
struct MessagingView: View {
    @EnvironmentObject var session: AtlasSession
    @State private var draft = ""

    var body: some View {
        NavigationStack {
            Group {
                if session.peerLive {
                    chat
                } else {
                    connectionPanel
                }
            }
            .navigationTitle("Messaging")
        }
    }

    // MARK: live chat (LK co-derived)

    private var chat: some View {
        VStack(alignment: .leading, spacing: 10) {
            ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(Array(session.messages.enumerated()), id: \.offset) { i, line in
                            Text(line).font(.system(.footnote, design: .monospaced))
                                .frame(maxWidth: .infinity, alignment: .leading).id(i)
                        }
                    }.padding(6)
                }
                .background(Color(.secondarySystemBackground)).cornerRadius(8)
                .onChange(of: session.messages.count) { _, c in
                    if c > 0 { withAnimation { proxy.scrollTo(c - 1, anchor: .bottom) } }
                }
            }
            HStack {
                TextField("message the group", text: $draft).textFieldStyle(.roundedBorder)
                    .onSubmit(sendIt)
                Button("Send", action: sendIt).disabled(draft.isEmpty)
            }
        }
        .padding()
    }

    // MARK: connection panel (not yet live)

    private var connectionPanel: some View {
        Form {
            Section {
                HStack {
                    ProgressView()
                    Text("Waiting for the group to come online")
                        .font(.subheadline.bold())
                }
                Text("Messaging opens once another member is online through the node and your phones co-derive the shared live key.")
                    .font(.caption).foregroundStyle(.secondary)
            }

            Section("This phone") {
                LabeledContent("you are", value: session.username.isEmpty ? "—" : session.username)
                LabeledContent("status", value: session.groupOnline ? "online at node" : "not connected")
                LabeledContent("group key", value: session.peerLive ? "co-derived ✓" : "waiting…")
            }

            Section("Node") {
                TextField("http://<mac-ip>:8787", text: $session.nodeURL)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                    .font(.system(.footnote, design: .monospaced))
                Button {
                    session.reconnectGroup()
                } label: {
                    Label("Reconnect", systemImage: "arrow.clockwise")
                }
            }

            Section("Others the node sees (opaque handles)") {
                if session.roster.isEmpty {
                    Text("no one else online yet").font(.caption).foregroundStyle(.secondary)
                } else {
                    ForEach(session.roster, id: \.self) { handle in
                        Label(AtlasSession.shortID(handle), systemImage: "person.fill")
                            .font(.system(.body, design: .monospaced))
                    }
                    Text("These are opaque mailbox handles — the node never sees anyone's name. Confirm you're talking to the right people with the safety number above, not by matching these.")
                        .font(.caption2).foregroundStyle(.secondary)
                }
            }

            Section("Live log") {
                ForEach(Array(session.log.enumerated().reversed().prefix(8)), id: \.offset) { _, l in
                    Text(l).font(.caption2.monospaced())
                }
            }
        }
    }

    private func sendIt() {
        let t = draft; draft = ""
        guard !t.isEmpty else { return }
        session.send(t)
    }
}
