import SwiftUI
import Combine
import CoreMotion
import AtlasCore

/// In-app hardware-seam test harness, built on the PROVEN real-R10 path (`RingProbe`:
/// scans-all, matches Nordic-UART, requests HR + accel). Runs the ring-dependent seams
/// on-device and records STRUCTURED results — printed to the Xcode console (`[SEAM]`
/// lines) and written to an exportable `hardware_results.md` in the app container.
///
/// Cleanly measurable here: liveness presence (live finger vs inert), and the same-body
/// characterization (phone IMU × ring accel correlation vs SAME_BODY_FLOOR). Containment
/// is CHARACTERIZED (the ring's presence-signal drop latency — which includes a ~5s PPG
/// freshness debounce; the real ≤3s key-wipe is a session-layer policy, measured elsewhere).
/// BLE Enc_stream is a code property of the production `R10BLEClient` (encrypt-on-receipt),
/// not the read path, so it's verified by inspection, not here.
struct SeamResult: Identifiable {
    let id = UUID()
    let seam: String
    let condition: String
    let measured: String
    let threshold: String
    let pass: Bool
    let at: Date
    var line: String {
        let f = DateFormatter(); f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return "| \(seam) | \(condition) | \(threshold) | \(pass ? "✅ PASS" : "❌ FAIL") | \(measured) | \(f.string(from: at)) |"
    }
}

@MainActor
final class HardwareSeamsModel: ObservableObject {
    @Published var results: [SeamResult] = []
    @Published var armLabel = ""
    @Published var sameBodyR: Double = 0
    @Published var armCountdown: Double = 0     // seconds left in the current arm's window
    @Published var liveStale: Double = 0        // seconds since the last live pulse (removal watchdog)

    let ring = RingProbe()                        // the proven real-R10 path
    private let motion = CMMotionManager()
    private var phoneAccel: [(t: Double, mag: Double)] = []

    // arm state
    private var arm: String?
    private var armCondition = ""
    private var armStart = 0.0
    private var armDeadline = 0.0
    private var sawPulse = false
    private var clearSince: Double?
    private var pollTask: Task<Void, Never>?

    private func now() -> Double { Date().timeIntervalSince1970 }

    func startPhoneMotion() {
        guard motion.isDeviceMotionAvailable, !motion.isDeviceMotionActive else { return }
        motion.deviceMotionUpdateInterval = 0.05
        // Deliver on the MAIN queue. This handler is @MainActor-isolated (the model is),
        // so delivering it on a background OperationQueue trips a Swift-6 executor
        // assertion (dispatch_assert_queue_fail → EXC_BREAKPOINT) the instant it fires —
        // that was the crash. Main queue = main actor = no trap; the work is trivial.
        motion.startDeviceMotionUpdates(to: .main) { [weak self] dm, _ in
            guard let self, let a = dm?.userAcceleration else { return }
            let mag = (a.x * a.x + a.y * a.y + a.z * a.z).squareRoot()
            let t = Date().timeIntervalSince1970
            self.phoneAccel.append((t, mag))
            let cutoff = t - 30
            if let i = self.phoneAccel.firstIndex(where: { $0.t >= cutoff }), i > 0 {
                self.phoneAccel.removeFirst(i)
            }
        }
    }

    func disconnect() {
        ring.disconnect()
        motion.stopDeviceMotionUpdates()
        if arm != nil { finish(false, "aborted: ring disconnected", "—") }
    }

    // MARK: arms

    func startArm(_ seam: String, condition: String, windowS: Double, label: String) {
        arm = seam; armCondition = condition; armLabel = label
        armStart = now(); armDeadline = armStart + windowS
        sawPulse = false; clearSince = nil
        pollTask?.cancel()
        pollTask = Task { @MainActor in
            while arm != nil {
                let t = now()
                // Freshness from the last live-pulse timestamp — robust to the ring going
                // silent on removal (the pulsePresent flag freezes; this staleness does not).
                let sinceFresh = t - ring.lastLivePulseTime
                let freshNow = sinceFresh < 1.5
                if freshNow { sawPulse = true; clearSince = nil }
                else if clearSince == nil { clearSince = t }
                armCountdown = max(0, armDeadline - t)   // live UI: window remaining
                liveStale = sinceFresh                   // live UI: removal watchdog
                switch seam {
                case "c-live":
                    if sawPulse { finish(true, "live pulse detected on-finger", "presence within \(Int(windowS))s") }
                    else if t >= armDeadline { finish(false, "no live pulse seen", "presence within \(Int(windowS))s") }
                case "c-reject":
                    // Auto-settle: pass only after presence has been CLEAR for a sustained 5s,
                    // so residual pulse right after removing the ring doesn't false-fail.
                    if let cs = clearSince, t - cs >= 5.0 {
                        finish(true, "no live pulse, sustained 5s on the inert object (auto-settled)", "no sustained presence")
                    } else if t >= armDeadline {
                        finish(false, "presence still detected near deadline — warm/active object or not settled", "no sustained presence")
                    }
                case "e-containment":
                    // Removal = no fresh pulse for ≥2s — works even when the ring goes silent
                    // on removal (pulsePresent would freeze; this staleness does not).
                    if sawPulse && sinceFresh >= 2.0 {
                        finish(sinceFresh <= 3.0, String(format: "removal detected %.1fs after last live pulse (2s no-pulse watchdog)", sinceFresh), "detect ≤ 3s")
                    } else if t >= armDeadline {
                        finish(false, sawPulse ? "still present at deadline — remove the ring during the window"
                                              : "no live session to break — wear the ring first", "detect ≤ 3s")
                    }
                case "same-body-bind", "same-body-proxy":
                    if t >= armDeadline {
                        let (r, n) = sameBodyCorrelation(from: armStart, to: t)
                        sameBodyR = r
                        let floor = 0.4   // parity: atlas.liveness.cross_device.SAME_BODY_FLOOR
                        if n < 6 {
                            finish(false, "insufficient ring-accel (n=\(n)) — R10 accel too sparse; confirms the streaming-IMU need",
                                   "enough samples to correlate")
                        } else if seam == "same-body-bind" {
                            finish(r >= floor, String(format: "corr r=%.2f (n=%d)", r, n), "r ≥ SAME_BODY_FLOOR(0.4)")
                        } else {
                            finish(r < floor, String(format: "corr r=%.2f (n=%d)", r, n), "r < 0.4 (proxy must NOT bind)")
                        }
                    }
                default: break
                }
                try? await Task.sleep(nanoseconds: 300_000_000)
            }
        }
    }

    // MARK: same-body math (mirrors atlas.liveness.cross_device: correlation vs a floor)

    private func sameBodyCorrelation(from: Double, to: Double) -> (r: Double, n: Int) {
        let ringSeries = ring.ringMotionSeries(windowS: to - from + 2).filter { $0.t >= from && $0.t <= to }
        let phoneSeries = phoneAccel.filter { $0.t >= from && $0.t <= to }
        let dt = 0.2
        var ps: [Double] = []; var rs: [Double] = []
        var g = from
        while g <= to {
            if let p = nearest(phoneSeries, g, 0.3), let rr = nearest(ringSeries, g, 0.3) { ps.append(p); rs.append(rr) }
            g += dt
        }
        guard ps.count >= 6 else { return (0, ps.count) }
        var best = pearson(ps, rs)
        for lag in [1, 2, -1, -2] {
            if lag > 0 { best = max(best, pearson(Array(ps.dropFirst(lag)), Array(rs.dropLast(lag)))) }
            else { let l = -lag; best = max(best, pearson(Array(ps.dropLast(l)), Array(rs.dropFirst(l)))) }
        }
        return (best, ps.count)
    }

    private func nearest(_ buf: [(t: Double, mag: Double)], _ t: Double, _ tol: Double) -> Double? {
        var best: Double? = nil; var bestDt = tol
        for s in buf { let d = abs(s.t - t); if d <= bestDt { bestDt = d; best = s.mag } }
        return best
    }

    private func pearson(_ a: [Double], _ b: [Double]) -> Double {
        let n = min(a.count, b.count); guard n >= 3 else { return 0 }
        let ma = a.prefix(n).reduce(0, +) / Double(n), mb = b.prefix(n).reduce(0, +) / Double(n)
        var num = 0.0, da = 0.0, db = 0.0
        for i in 0..<n { let xa = a[i] - ma, xb = b[i] - mb; num += xa * xb; da += xa * xa; db += xb * xb }
        let den = (da * db).squareRoot()
        return den > 0 ? num / den : 0
    }

    private func finish(_ pass: Bool, _ measured: String, _ threshold: String) {
        let r = SeamResult(seam: arm ?? "?", condition: armCondition, measured: measured,
                           threshold: threshold, pass: pass, at: Date())
        results.insert(r, at: 0)
        print("[SEAM] \(r.line)")
        writeFile()
        arm = nil; armLabel = ""; armCountdown = 0; pollTask?.cancel(); pollTask = nil
    }

    // MARK: export

    private var fileURL: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("hardware_results.md")
    }
    private func writeFile() {
        var md = "# Hardware seam results (exported from the app)\n\n"
        md += "| Seam | Condition | Threshold | Verdict | Measured | Time |\n"
        md += "|------|-----------|-----------|---------|----------|------|\n"
        md += results.map { $0.line }.joined(separator: "\n") + "\n"
        try? md.write(to: fileURL, atomically: true, encoding: .utf8)
    }
    func exportURL() -> URL { writeFile(); return fileURL }
}

struct HardwareSeamsView: View {
    @StateObject private var model = HardwareSeamsModel()

    var body: some View {
        NavigationStack {
            List {
                SeamRingSection(ring: model.ring, model: model)
                if !model.armLabel.isEmpty {
                    Section("Running") {
                        HStack { ProgressView(); Text(model.armLabel).font(.footnote) }
                        HStack {
                            Text(String(format: "%.0fs left", model.armCountdown)).font(.callout.monospaced().bold())
                            Spacer()
                            Text(String(format: "since pulse: %.1fs", model.liveStale))
                                .font(.callout.monospaced())
                                .foregroundStyle(model.liveStale >= 2 ? .green : .orange)
                        }
                    }
                }
                Section("Run a seam (position the ring, then tap)") {
                    Button("① Liveness — worn (presence)") {
                        model.startArm("c-live", condition: "worn", windowS: 20, label: "wear the ring, hold still…")
                    }
                    Button("② Reject — inert object, e.g. desk (no presence)") {
                        model.startArm("c-reject", condition: "inert object (desk)", windowS: 20, label: "ring on the desk/table (auto-settles) ~20s…")
                    }
                    Button("③ Containment — remove ring (2s no-pulse watchdog)") {
                        model.startArm("e-containment", condition: "ring removed", windowS: 30, label: "REMOVE the ring — watch ‘since pulse’ climb past 2s")
                    }
                    Button("⑤ Same-body — phone+ring on you, MOVE (should bind)") {
                        model.startArm("same-body-bind", condition: "phone+ring one body", windowS: 15, label: "wear ring, hold phone, move ~15s…")
                    }
                    Button("⑥ Same-body — ring on table, MOVE phone (should NOT bind)") {
                        model.startArm("same-body-proxy", condition: "ring on table, phone moved", windowS: 15, label: "ring on the table, move the phone ~15s…")
                    }
                }
                Section("Results (newest first) — also in Xcode console") {
                    if model.results.isEmpty { Text("no runs yet").foregroundStyle(.secondary).font(.footnote) }
                    ForEach(model.results) { r in
                        VStack(alignment: .leading, spacing: 2) {
                            Text("\(r.pass ? "✅" : "❌")  \(r.seam) · \(r.condition)").font(.subheadline.bold())
                            Text(r.measured).font(.caption).foregroundStyle(.secondary)
                            Text("threshold: \(r.threshold)").font(.caption2).foregroundStyle(.secondary)
                        }
                    }
                    ShareLink("Export results file", item: model.exportURL())
                }
                Section {
                    Text("Liveness/reject read the ring's live-PPG presence (live finger vs inert object). Same-body correlates the PHONE motion with the RING accel vs SAME_BODY_FLOOR(0.4) — the R10's accel is intermittent, so a low/insufficient result is itself the finding (it needs a streaming-IMU ring). Containment here CHARACTERIZES the ring's presence drop (a ~5s PPG debounce), not the crypto key-wipe. Same-body proxy (ring on table) is how a ‘second live body’ is actually rejected — by binding, not liveness.")
                        .font(.caption2).foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Seams")
            .onAppear { model.startPhoneMotion() }
        }
    }
}

/// Ring status + scan/connect, observing `RingProbe` natively (no manual objectWillChange
/// forwarding — that reentrancy is what crashed on scan). `model` supplies same-body r.
struct SeamRingSection: View {
    @ObservedObject var ring: RingProbe
    @ObservedObject var model: HardwareSeamsModel
    var body: some View {
        Section("Ring (Colmi R10 · proven RingProbe path)") {
            LabeledContent("Status", value: ring.status)
            LabeledContent("Connected", value: ring.connectedName.isEmpty ? "—" : ring.connectedName)
            LabeledContent("Live", value: ring.liveness)
            LabeledContent("Accel stream", value: ring.isStreamingAccel
                           ? String(format: "%.0f Hz", ring.accelHz) : "none yet (R10 accel is intermittent)")
            LabeledContent("same-body r", value: String(format: "%.2f", model.sameBodyR))
            if ring.connectedName.isEmpty {
                Button("Scan for ring") { ring.scanAll() }
                ForEach(ring.devices) { d in
                    Button { ring.connect(d) } label: {
                        HStack {
                            Text(d.name.isEmpty ? "unknown device" : d.name)
                            Spacer(); Text("\(d.rssi) dBm").foregroundStyle(.secondary)
                        }.font(.footnote)
                    }
                }
            } else {
                Button("Disconnect", role: .destructive) { model.disconnect() }
            }
        }
    }
}
