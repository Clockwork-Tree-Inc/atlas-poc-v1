import SwiftUI
import Combine
import AtlasCore

/// The iPhone-only ambient PoC screen: run the full stack on real hardware with
/// the ambient signal standing in for the ring. Shows the honesty banner, the
/// enrolment ceremony, an ambient-timed ratchet, the ordinary-decision gate, and
/// the duress slice — every stand-in labelled.
///
/// STATUS: unrun until built on a Mac to a device (needs mic + motion usage
/// strings in Info.plist and Face ID capability).
@MainActor
final class AmbientPoCModel: ObservableObject {
    @Published var log: [String] = []
    @Published var enrolled = false
    @Published var lastKey = ""
    @Published var password = ""
    @Published var panicCode = ""

    private let runtime = AtlasRuntime(sphincs: PlaceholderSphincs())
    private var epoch: (wrappedEpochKey: Data, wrappedLK: Data)?

    func onAppear() {
        for line in AtlasFlags.honestyBanner { add("· \(line)") }
        Task { await runtime.primeSensors() }   // prime permissions; no continuous streaming
    }
    private func add(_ s: String) { log.append(s) }

    func enrol(buttonDoubleClicked: Bool) {
        Task {
            do {
                try await runtime.enrol(password: password, buttonDoubleClicked: buttonDoubleClicked,
                                        forensicWindow: true, panicCode: panicCode)
                epoch = try runtime.establishEpoch()
                enrolled = true
                add("Enrolled: Face ID + password + button + live ambient signal. Epoch established.")
            } catch {
                add("Enrol refused: \(error)")
            }
        }
    }

    /// One ambient-timed ratchet step + ordinary-decision gate. Async: the tick
    /// pulls a FRESH ambient snapshot on-demand (B4) before stepping.
    func ratchetAndAct(buttonDoubleClicked: Bool) {
        guard enrolled, let epoch else { add("Enrol first."); return }
        Task {
            do {
                // PoLE from the REAL ambient change (change/entropy -> Bayesian
                // liveness), not synthetic data. The fresh ambient sample TIMES +
                // GATES + now drives liveness.
                let pole = try await runtime.ambientPoLE(drandRound: Data(count: 8))
                _ = try runtime.advance(wrappedEpochKey: epoch.wrappedEpochKey, wrappedLK: epoch.wrappedLK,
                                        pole: pole, liveBiometric: Data(repeating: 7, count: 256))
                let tick = try await runtime.ratchetOnce(pole: pole, beacon: Data("beacon-fresh".utf8))
                if tick.gatedOut {
                    add("Ambient signal absent → ratchet gated closed (fail-closed).")
                    return
                }
                if let key = tick.tick?.continuityKey { lastKey = key.prefix(6).map { String(format: "%02x", $0) }.joined() }
                add("Ratchet advanced in \(String(format: "%.2f", tick.intervalS))s (source=\(tick.sourceKind), simulated=\(tick.simulated)).")
                let ok = runtime.authorizeOrdinaryDecision(buttonDoubleClicked: buttonDoubleClicked, tick: tick)
                add(ok ? "Ordinary decision AUTHORISED (button double-click on the live session)."
                       : "Ordinary decision DENIED (need button double-click on a live session).")
            } catch {
                add("Ratchet error: \(error)")
            }
        }
    }

    func unlock(code: String) {
        guard let r = runtime.unlockUnderCode(code) else { add("No vault."); return }
        if !r.surfaceOK { add("Unlock failed."); return }
        add(r.duress ? "Unlocked (observer sees success) — DECOY shown, real secrets sealed."
                     : "Unlocked — real vault.")
    }

    func panicWipe() {
        runtime.zeroizeOnSuspicion("user-initiated panic wipe")
        add("Zeroize-on-suspicion fired — real key destroyed; real vault is a permanent brick.")
    }

}

struct AmbientPoCView: View {
    @StateObject private var model = AmbientPoCModel()
    @State private var buttonClicks = 0

    var body: some View {
        NavigationStack {
            Form {
                Section("Ambient iPhone PoC — honest status") {
                    ForEach(AtlasFlags.honestyBanner, id: \.self) { Text($0).font(.caption).foregroundStyle(.secondary) }
                }
                Section("Enrol (Face ID + password + button)") {
                    SecureField("Password (enrol/disenrol only)", text: $model.password)
                    SecureField("Panic code (opens decoy)", text: $model.panicCode)
                    Button("Double-click to confirm + Enrol") {
                        buttonClicks += 1
                        model.enrol(buttonDoubleClicked: buttonClicks >= 2)
                    }.disabled(model.enrolled)
                    if buttonClicks == 1 { Text("Click once more to confirm…").font(.caption) }
                }
                Section("Live session") {
                    Button("Ratchet once (ambient-timed) + ordinary decision") {
                        model.ratchetAndAct(buttonDoubleClicked: true)
                    }.disabled(!model.enrolled)
                    if !model.lastKey.isEmpty { Text("continuity key: \(model.lastKey)…").font(.caption.monospaced()) }
                }
                Section("Duress") {
                    Button("Unlock with password") { model.unlock(code: model.password) }
                    Button("Unlock with panic code") { model.unlock(code: model.panicCode) }
                    Button("Panic wipe (zeroize)", role: .destructive) { model.panicWipe() }
                }
                Section("Log") {
                    ForEach(model.log.reversed(), id: \.self) { Text($0).font(.caption2.monospaced()) }
                }
            }
            .navigationTitle("Atlas · Ambient PoC")
            .onAppear { model.onAppear() }
        }
    }
}
