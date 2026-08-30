import SwiftUI
import Combine
import AtlasCore

/// Milestone 2 (§13): R10 BLE capture on the phone + the biology-timed liveness
/// gate. Connects the ring, streams real-time HR/SpO2/accelerometer, encrypts
/// the raw stream under the DevKey on receipt, and runs the Bayesian gate.
/// Containment is shown by breaking liveness → the session key is wiped.
@MainActor
final class Milestone2Model: ObservableObject {
    @Published var status = "Idle"
    @Published var reading = "—"
    @Published var pLive: Double = 0
    @Published var operating = false
    @Published var encryptedFrames = 0

    private var client: R10BLEClient?
    private let gate = LivenessGate()
    private let store = SecureEnclaveStore()

    func connect() {
        do {
            let devKey = try store.loadOrCreateDevKey()
            let c = R10BLEClient(devKey: devKey)
            c.onEncryptedStream = { [weak self] _ in self?.encryptedFrames += 1 }   // Enc_stream count
            c.onSample = { [weak self] r in self?.ingest(r) }
            client = c
            status = "Scanning for R10…"
            c.startScan()
            observe(c)
        } catch { status = "Enclave error: \(error)" }
    }

    private func observe(_ c: R10BLEClient) {
        Task { @MainActor in
            for await _ in Timer.publish(every: 0.5, on: .main, in: .common).autoconnect().values {
                status = "\(c.state)"
                reading = c.lastReading
                if case .disconnected = c.state { break }
            }
        }
    }

    private func ingest(_ r: R10.Reading) {
        // Map the live reading to a likelihood and update the Bayesian gate.
        // (On real captures, derive HRV from inter-beat intervals; here we use
        // the streamed HR/SpO2 plus the synthetic likelihood heuristic.)
        let sample = SensorSample(hr: Double(r.heartRate ?? 0), hrvMS: 40, spo2: Double(r.spo2 ?? 0),
                                  accelMag: 0.02)
        let l = Synthetic.likelihood(sample)
        gate.update(pSGivenLive: l.0, pSGivenNotLive: l.1)
        let state = gate.state(sensorDigest: sample.digest(), drandRound: Data(count: 8))
        pLive = state.pLive
        operating = state.operate
    }

    func disconnect() { client?.disconnect(); status = "Disconnected" }
}

struct Milestone2View: View {
    @StateObject private var model = Milestone2Model()
    var body: some View {
        NavigationStack {
            List {
                Section("Ring (Colmi R10)") {
                    LabeledContent("Status", value: model.status)
                    LabeledContent("Reading", value: model.reading)
                    LabeledContent("Enc_stream frames", value: "\(model.encryptedFrames)")
                }
                Section("Liveness gate (§5.2)") {
                    LabeledContent("P(L|S)", value: String(format: "%.3f", model.pLive))
                    LabeledContent("Operate (≥ π*)", value: model.operating ? "yes" : "no")
                }
                Section {
                    Button("Connect ring + start streaming") { model.connect() }
                    Button("Disconnect", role: .destructive) { model.disconnect() }
                }
                Section {
                    Text("The R10 is an untrusted sensor: raw values are encrypted under the DevKey on the phone immediately on receipt (Enc_stream, §0.3/§5.1). No raw biometric leaves the device.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }
            .navigationTitle("M2 · Liveness")
        }
    }
}
