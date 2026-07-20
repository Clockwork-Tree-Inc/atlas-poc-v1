import SwiftUI
import UniformTypeIdentifiers

/// Distributed identity recovery. tskSeed = userPart ⊕ serverPart:
///  - userPart is your POSSESSION — held whole on your USB and your wallet (phone).
///    EITHER one is enough. It's only half the seed, so a lost factor recovers nothing.
///  - serverPart is split k-of-N across the server nodes and is released ONLY by the full
///    in-person ceremony at a recovery server: you physically appear, a human verifies your
///    live presence, your Face ID makes a server-side signature, and you give your password.
/// Recovery needs BOTH halves — a stolen USB or wallet alone can't rebuild you.
struct RecoveryView: View {
    @EnvironmentObject var session: AtlasSession
    @State private var usbData: Data?
    @State private var showExporter = false
    @State private var showImporter = false
    // Recovery inputs:
    @State private var presentedUSB: Data?     // the USB the user presents at the server
    @State private var walletPresent = false   // "my wallet (this phone) is present"
    @State private var atServer = false        // physically at the recovery server
    @State private var humanVerified = false   // a human at the server verified my presence
    @State private var password = ""

    var body: some View {
        NavigationStack {
            Form {
                Section("How recovery works") {
                    Text("Your seed = userPart ⊕ serverPart. The userPart is your possession — your USB or your wallet, either one. The serverPart lives across the nodes and is released only in person at a recovery server: physical presence + a human verifying you + your Face ID signature + your password. A stolen USB or wallet is only half — it recovers nothing alone.")
                        .font(.caption).foregroundStyle(.secondary)
                }

                Section("At enrol — write your USB factor") {
                    Button("Write USB recovery factor to the drive") {
                        usbData = session.recoveryUSBShare()
                        showExporter = usbData != nil
                    }.disabled(!session.recoveryArmed)
                    Text(session.recoveryArmed
                         ? "armed ✓ — your USB and your wallet each hold the user half; either is enough. It's half the seed, so a lost drive is useless without the server ceremony."
                         : "enrol first")
                        .font(.caption).foregroundStyle(.secondary)
                }

                Section("Recover — your possession (either one)") {
                    Toggle("My wallet (this phone) is present", isOn: $walletPresent)
                    Button(presentedUSB == nil ? "Present my USB share" : "USB presented ✓") { showImporter = true }
                    Text("Either your USB or your wallet satisfies the user half.")
                        .font(.caption).foregroundStyle(.secondary)
                }

                Section("Recover — the server ceremony (all required)") {
                    Toggle("Physically at the recovery server", isOn: $atServer)
                    Toggle("A human verified my live presence", isOn: $humanVerified)
                    SecureField("Recovery password", text: $password)
                    Button("Sign with Face ID & release the server share") { recover() }
                        .disabled(!session.recoveryArmed)
                    Text("Your Face ID makes the server-side signature. Try it missing a factor — no USB/wallet, not at the server, no human check, wrong password, or cancel Face ID — and the server share stays BLOCKED. All four present → your identity is rebuilt.")
                        .font(.caption).foregroundStyle(.secondary)
                }

                Section("Log") {
                    ForEach(Array(session.log.enumerated().reversed().prefix(8)), id: \.offset) { _, l in
                        Text(l).font(.caption2.monospaced())
                    }
                }
            }
            .navigationTitle("Recovery")
            .fileExporter(isPresented: $showExporter,
                          document: usbData.map { RecoveryFile(data: $0) },
                          contentType: .data, defaultFilename: "atlas-recovery.share") { _ in }
            .fileImporter(isPresented: $showImporter, allowedContentTypes: [.data, .item]) { result in
                if case .success(let url) = result {
                    let need = url.startAccessingSecurityScopedResource()
                    defer { if need { url.stopAccessingSecurityScopedResource() } }
                    presentedUSB = try? Data(contentsOf: url)
                }
            }
        }
    }

    private func recover() {
        Task { @MainActor in
            // The Face ID SERVER-SIDE SIGNATURE: a per-action, Secure-Enclave-gated confirm
            // that the recovery server verifies. No confirm → the server share is never released.
            let faceID: Bool
            do {
                faceID = try await IntentGesture.confirm(
                    action: "Sign your recovery at the server (verified presence)")
            } catch {
                session.note("recovery BLOCKED: Face ID signature not provided (\(error.localizedDescription)).")
                return
            }
            _ = session.recoverIdentity(usbData: presentedUSB, walletPresent: walletPresent,
                                        atServer: atServer, humanVerified: humanVerified,
                                        faceIDSignature: faceID, password: password)
        }
    }
}

/// Minimal file wrapper so `.fileExporter` can write the recovery factor.
struct RecoveryFile: FileDocument {
    static var readableContentTypes: [UTType] { [.data] }
    let data: Data
    init(data: Data) { self.data = data }
    init(configuration: ReadConfiguration) throws { data = configuration.file.regularFileContents ?? Data() }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper { FileWrapper(regularFileWithContents: data) }
}
