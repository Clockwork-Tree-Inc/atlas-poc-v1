import SwiftUI

/// Node settings — point the app at YOUR node (a VPS on the private Tailscale mesh, your laptop,
/// or the LAN Mac). The relay URL carries messaging/roster; the SearXNG URL gives the AI live
/// wider-web search from your own box (no vendor surface). See deploy/README.md for bring-up.
struct NodeSettingsView: View {
    @EnvironmentObject var session: AtlasSession
    @State private var url = ""
    @State private var searx = ""

    var body: some View {
        Form {
            Section("Relay node") {
                TextField("http://100.x.y.z:8787", text: $url)
                    .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                HStack {
                    Circle().fill(session.nodeConnected ? .green : .orange).frame(width: 8, height: 8)
                    Text(session.nodeConnected ? "connected" : "not connected")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            Section("Live web search (node SearXNG)") {
                TextField("http://100.x.y.z:8888 (empty = off)", text: $searx)
                    .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
            }
            Section {
                Button("Apply & reconnect") {
                    session.nodeURL = url.trimmingCharacters(in: .whitespaces)
                    session.nodeSearchURL = searx.trimmingCharacters(in: .whitespaces)
                    session.reconnectGroup()
                }
            } footer: {
                Text("On the private mesh, use the box's Tailscale IP (100.x…). Content is sealed at the app layer regardless of transport; the mesh keeps the beta off the public internet.")
            }
        }
        .navigationTitle("Node")
        .onAppear { url = session.nodeURL; searx = session.nodeSearchURL }
    }
}
