import SwiftUI
import Combine
import UIKit
import UniformTypeIdentifiers

/// Battery / attestation-cost test. Toggle whether a full PQC LivenessAttestation is
/// signed EVERY ratchet tick vs only on demand, run a raw signing benchmark, and
/// watch the live battery drain — so the per-tick cost is measured, not guessed.
struct DiagnosticsView: View {
    @EnvironmentObject var session: AtlasSession
    @State private var level: Float = -1
    @State private var startLevel: Float = -1
    @State private var startTime = Date()
    @State private var proofLabel = ""
    @State private var proofData: Data?
    @State private var showExporter = false
    private let tick = Timer.publish(every: 5, on: .main, in: .common).autoconnect()

    var body: some View {
        NavigationStack {
            List {
                Section("Attestation mode") {
                    Toggle("Sign a full PQC attestation every tick", isOn: $session.attestEveryTick)
                    Text("OFF = sign only on demand (message / capture / auth). ON = sign every ratchet tick — measure the cost below.")
                        .font(.caption).foregroundStyle(.secondary)
                    if session.sigCount > 0 {
                        Text("per-tick sigs: \(session.sigCount) · avg \(String(format: "%.2f", session.avgSignMs)) ms/sig")
                            .font(.footnote.monospaced())
                    }
                    Button("Run signing benchmark (200 sigs)") { session.signBenchmark(200) }
                }
                Section("Battery") {
                    Text(level >= 0 ? "level: \(Int(level * 100))%  ·  \(stateText)" : "battery level unavailable")
                        .font(.footnote.monospaced())
                    if startLevel >= 0 && level >= 0 {
                        let mins = Date().timeIntervalSince(startTime) / 60
                        let usedPct = Double(startLevel - level) * 100
                        Text(mins >= 1
                             ? String(format: "since opened: %.0f min · %.1f%% used · ≈ %.1f%%/hr", mins, usedPct, usedPct / (mins / 60))
                             : String(format: "since opened: %.0f min · %.1f%% used", mins, usedPct))
                            .font(.footnote.monospaced()).foregroundStyle(.secondary)
                    }
                    Text("Turn per-tick ON, keep this tab open a while, watch %/hr; then compare with it OFF. Unplug the phone for a real reading.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section("Storage policy — you decide") {
                    Toggle("Keep a rolling proof log", isOn: $session.proofLogging)
                    Stepper("Retention: last \(Int(session.retentionHours)) h", value: $session.retentionHours, in: 1...168, step: 1)
                    Text("rolling log: \(session.proofTicks) attestations retained")
                        .font(.footnote.monospaced()).foregroundStyle(.secondary)
                    HStack {
                        Button("Export rolling log") { proofData = session.exportRollingLog(); showExporter = true }
                            .disabled(session.proofTicks == 0)
                        Spacer()
                        Button("Clear", role: .destructive) { session.clearProofLog() }
                    }
                    Text("Off = cheapest (sign only on demand). Rolling = keep the last N hours (auto-pruned) so any recent material can be proven. Or record a specific item below.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section("Proof recording (opt-in, per item)") {
                    if session.proofRecording {
                        Text("● recording — \(session.proofTicks) live attestations captured")
                            .font(.footnote.monospaced()).foregroundStyle(.red)
                        Button("Stop & export proof") {
                            proofData = session.stopProofBundle()
                            showExporter = true
                        }
                    } else {
                        TextField("What is this proof for? (e.g. my-video)", text: $proofLabel)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                        Button("Start proof recording") { session.startProof(label: proofLabel.isEmpty ? "recording" : proofLabel) }
                            .disabled(!session.peerLive)
                    }
                    Text("Capture the per-tick live id-attestations across a recording (a video you make), then save/export the proof that a live, identity-attested human was present throughout. You only pay the storage when it's worth it.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section("Live session") {
                    Text("ratchet ticks: \(session.ratchetTicks) · presence \(session.presenceLive ? "✓" : "gated")")
                        .font(.footnote.monospaced())
                }
            }
            .navigationTitle("Diagnostics")
            .fileExporter(isPresented: $showExporter,
                          document: proofData.map { ProofFile(data: $0) },
                          contentType: .json,
                          defaultFilename: "atlas-proof-\(proofLabel.isEmpty ? "recording" : proofLabel)") { _ in }
            .onAppear {
                UIDevice.current.isBatteryMonitoringEnabled = true
                startLevel = UIDevice.current.batteryLevel; level = startLevel; startTime = Date()
            }
            .onReceive(tick) { _ in level = UIDevice.current.batteryLevel }
        }
    }

    private var stateText: String {
        switch UIDevice.current.batteryState {
        case .charging: return "charging"
        case .full: return "full"
        case .unplugged: return "on battery"
        default: return "unknown"
        }
    }
}

/// Exportable proof-bundle file (the captured live-attestation chain, JSON).
struct ProofFile: FileDocument {
    static var readableContentTypes: [UTType] { [.json] }
    let data: Data
    init(data: Data) { self.data = data }
    init(configuration: ReadConfiguration) throws { data = configuration.file.regularFileContents ?? Data() }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper { FileWrapper(regularFileWithContents: data) }
}
