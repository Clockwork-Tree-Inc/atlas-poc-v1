import SwiftUI

/// Duress: the panic code opens a DECOY vault whose surface is identical to the real
/// one, and zeroize-on-suspicion destroys the real key. (The `duress` flag is shown
/// here only to demonstrate the mechanism — in production the surface is identical
/// and never reveals which code was used.)
struct DuressView: View {
    @EnvironmentObject var session: AtlasSession
    @State private var code = ""
    @State private var log: [String] = []

    var body: some View {
        NavigationStack {
            Form {
                Section("Unlock") {
                    SecureField("password or panic code", text: $code)
                    Button("Unlock") { unlock() }.disabled(code.isEmpty)
                    Text("Your password opens the real vault; your panic code opens a decoy that looks identical. An observer can't tell which you used.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section("Duress") {
                    Button("Panic wipe (zeroize the real key)", role: .destructive) {
                        session.panicWipe()
                        log.append("panic wipe fired — real key destroyed; session locked")
                    }
                    Text("Destroys the real key permanently (a brick); the decoy survives. Also locks the whole session.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section("Result") {
                    ForEach(Array(log.enumerated().reversed()), id: \.offset) { _, l in
                        Text(l).font(.caption2.monospaced())
                    }
                }
            }
            .navigationTitle("Duress")
        }
    }

    private func unlock() {
        guard let r = session.unlockUnderCode(code) else {
            log.append("no duress vault — enrol with a panic code set"); return
        }
        guard r.surfaceOK else { log.append("unlock failed (wrong code)"); return }
        log.append(r.duress ? "unlocked ✓ (observer sees success) — DECOY shown, real secrets sealed"
                            : "unlocked ✓ — real vault")
        code = ""
    }
}
