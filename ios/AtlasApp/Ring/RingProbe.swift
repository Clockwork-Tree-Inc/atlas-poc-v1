import Foundation
import Combine
import CoreBluetooth
import AtlasCore

/// On-device R10 discovery probe (DEV tool). Scans ALL peripherals, connects to a
/// chosen one, enumerates every service/characteristic, subscribes to notifiable
/// characteristics, and surfaces the raw packets ON SCREEN — so the real GATT layout
/// + wire format can be read off the phone. Holds NO secrets and does no crypto.
///
/// Robust streaming: it targets ONLY the Nordic-UART write characteristic (writing
/// the HR command to unrelated characteristics makes the ring drop the link), sends
/// the start command shortly after connect, keeps it alive, and auto-reconnects.
@MainActor
final class RingProbe: NSObject, ObservableObject {

    struct Found: Identifiable {
        let id: UUID; let name: String; let rssi: Int; let peripheral: CBPeripheral
    }
    struct Char: Identifiable { let id = UUID(); let service: String; let uuid: String; let props: String }
    struct Packet: Identifiable { let id = UUID(); let t: String; let char: String; let hex: String; let bytes: [UInt8] }

    @Published var status = "idle"
    @Published var reading = "—"            // plain-language decode of the newest HR frame
    @Published var liveness = "—"           // real ring-liveness verdict (HR + on-body motion)
    @Published private(set) var pulsePresent = false   // live pulse right now (drives the presence gate)
    @Published private(set) var bpm = 0     // best current heart-rate estimate (0 = none yet)
    @Published private(set) var bpmSource = ""   // "ring" | "PPG" | "" — where bpm came from
    @Published private(set) var sampleHz = 0.0   // non-zero PPG sample rate (usable for bpm)
    @Published private(set) var frameHz = 0.0    // total 0x69 frame rate (what the ring streams)
    @Published var devices: [Found] = []

    // Live decode state for the on-device liveness verdict.
    private var lastHR: Double = 0
    private var lastHRTime: TimeInterval = 0
    private var accelMean: SIMD3<Double> = .zero
    private var lastMotion: Double = 0
    private var hrWindow: [Double] = []
    private var ppgWindow: [Double] = []       // raw green-LED PPG amplitude window
    private var ppgSamples: [(t: TimeInterval, v: Double)] = []  // timestamped PPG for bpm-from-waveform
    private var frameTimes: [TimeInterval] = []                  // recent NON-ZERO PPG arrivals (usable-rate meter)
    private var allFrameTimes: [TimeInterval] = []               // recent ALL 0x69 arrivals (stream-rate meter)
    private var accelSamples: [(t: TimeInterval, mag: Double)] = []  // recent ring accel (for the handshake tap bind)
    private var accelFrameTimes: [TimeInterval] = []             // accel arrivals (does the R10 even stream accel, how fast?)
    @Published private(set) var accelHz = 0.0                    // measured accel frame rate (0 = no accel stream)
    private var bpmEstimates: [(t: TimeInterval, bpm: Double)] = []  // accepted per-window bpm, median-smoothed
    @Published var chars: [Char] = []
    @Published var packets: [Packet] = []            // most-recent-first, capped
    @Published var connectedName = ""

    private var central: CBCentralManager!
    private var target: CBPeripheral?
    private var rxChar: CBCharacteristic?             // Nordic-UART write (6E400002)
    private var notifyChars: [CBCharacteristic] = []
    private var keepAlive: Timer?
    private var wantStream = false
    private let maxPackets = 60

    // Nordic-UART-style ids the R10 uses (write / notify). Matched case-insensitively.
    private let rxSuffix = "6E400002"
    private let txSuffix = "6E400003"

    override init() { super.init(); central = CBCentralManager(delegate: self, queue: .main) }

    func scanAll() {
        guard central.state == .poweredOn else { status = "bluetooth off/unauthorized"; return }
        devices.removeAll(); status = "scanning…"
        central.scanForPeripherals(withServices: nil, options: [CBCentralManagerScanOptionAllowDuplicatesKey: false])
    }

    func connect(_ f: Found) {
        central.stopScan()
        target = f.peripheral; f.peripheral.delegate = self
        connectedName = f.name; wantStream = true
        chars.removeAll(); packets.removeAll(); notifyChars.removeAll(); rxChar = nil
        status = "connecting to \(f.name)…"
        central.connect(f.peripheral, options: nil)
    }

    func disconnect() {
        wantStream = false; keepAlive?.invalidate()
        if let t = target { central.cancelPeripheralConnection(t) }
        status = "disconnected"
        pulsePresent = false; ppgWindow.removeAll(); ppgSamples.removeAll(); lastHRTime = 0
        bpm = 0; bpmSource = ""; sampleHz = 0; frameHz = 0; accelHz = 0
        frameTimes.removeAll(); allFrameTimes.removeAll(); bpmEstimates.removeAll()
        accelSamples.removeAll(); accelFrameTimes.removeAll()
        liveness = "absent — ring disconnected"
    }

    /// Send the real-time-HR start command to the Nordic RX characteristic ONLY.
    func startStream() {
        guard let t = target, let rx = rxChar else { event("no Nordic RX char to write"); return }
        let type: CBCharacteristicWriteType = rx.properties.contains(.writeWithoutResponse) ? .withoutResponse : .withResponse
        t.writeValue(R10.startRealTimeHeartRate(), for: rx, type: type)
        // Also try to enable the accelerometer stream (0x6F) — the on-body / anti-
        // removal signal. If the ring doesn't stream on this command we'll see no
        // 0x6F frames and fall back to HR-only presence.
        t.writeValue(R10.makePacket(R10.Command.accelStream.rawValue, payload: [0x01]), for: rx, type: type)
        event("→ START_HR + START_ACCEL written to \(short(rx.uuid))")
        keepAlive?.invalidate()
        // Ping the ring often — some R0x firmware only emits a burst of PPG per CONTINUE,
        // so a faster cadence raises the effective sample rate (also prevents the ~5s
        // real-time timeout). 0.8s is well under the timeout and keeps the stream warm.
        keepAlive = Timer.scheduledTimer(withTimeInterval: 0.8, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self, let t = self.target, let rx = self.rxChar else { return }
                let ty: CBCharacteristicWriteType = rx.properties.contains(.writeWithoutResponse) ? .withoutResponse : .withResponse
                t.writeValue(R10.keepAliveRealTime(), for: rx, type: ty)
            }
        }
    }

    private func event(_ s: String) {
        packets.insert(Packet(t: Self.stamp(), char: "·evt", hex: s, bytes: []), at: 0)
        if packets.count > maxPackets { packets.removeLast(packets.count - maxPackets) }
    }
    private func logPacket(_ char: String, _ data: Data) {
        let b = [UInt8](data)
        packets.insert(Packet(t: Self.stamp(), char: short(CBUUID(string: char)),
                              hex: data.map { String(format: "%02x", $0) }.joined(), bytes: b), at: 0)
        if packets.count > maxPackets { packets.removeLast(packets.count - maxPackets) }
    }
    private func short(_ u: CBUUID) -> String { String(u.uuidString.prefix(8)) }
    private static func stamp() -> String {
        let d = Date().timeIntervalSince1970
        return String(format: "%02d.%03d", Int(d) % 100, Int((d.truncatingRemainder(dividingBy: 1)) * 1000))
    }
}

extension RingProbe: @preconcurrency CBCentralManagerDelegate {
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        switch central.state {
        case .poweredOn: status = "ready — tap Scan"
        case .poweredOff: status = "bluetooth off"
        case .unauthorized: status = "bluetooth not authorized for this app"
        default: status = "bluetooth unavailable"
        }
    }
    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                        advertisementData: [String: Any], rssi RSSI: NSNumber) {
        let advName = (advertisementData[CBAdvertisementDataLocalNameKey] as? String) ?? peripheral.name ?? ""
        guard !advName.isEmpty else { return }
        if devices.contains(where: { $0.id == peripheral.identifier }) { return }
        devices.append(Found(id: peripheral.identifier, name: advName, rssi: RSSI.intValue, peripheral: peripheral))
        devices.sort { $0.rssi > $1.rssi }
    }
    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        status = "connected — discovering services…"; event("connected")
        peripheral.discoverServices(nil)
    }
    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        status = "connect failed: \(error?.localizedDescription ?? "?")"
    }
    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        keepAlive?.invalidate()
        event("DISCONNECTED: \(error?.localizedDescription ?? "clean")")
        status = "disconnected — \(wantStream ? "reconnecting…" : "idle")"
        pulsePresent = false; lastHRTime = 0; bpm = 0; bpmSource = ""; sampleHz = 0
        if wantStream { central.connect(peripheral, options: nil) }   // auto-reconnect
    }
}

extension RingProbe: @preconcurrency CBPeripheralDelegate {
    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        for s in peripheral.services ?? [] { peripheral.discoverCharacteristics(nil, for: s) }
    }
    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        for c in service.characteristics ?? [] {
            var props: [String] = []
            if c.properties.contains(.read) { props.append("read") }
            if c.properties.contains(.write) { props.append("write") }
            if c.properties.contains(.writeWithoutResponse) { props.append("writeNR") }
            if c.properties.contains(.notify) { props.append("notify") }
            if c.properties.contains(.indicate) { props.append("indicate") }
            chars.append(Char(service: short(service.uuid), uuid: c.uuid.uuidString, props: props.joined(separator: ",")))

            let up = c.uuid.uuidString.uppercased()
            // Subscribe ONLY to the Nordic-UART TX (the HR stream). Subscribing to the
            // ring's OTHER notify characteristics (some require encryption) is what makes
            // iOS pop the pairing prompt — and we don't need them.
            if up.contains(txSuffix), c.properties.contains(.notify) || c.properties.contains(.indicate) {
                peripheral.setNotifyValue(true, for: c); notifyChars.append(c)
            }
            if up.contains(rxSuffix) { rxChar = c }
            // fallback: first writable char if the Nordic RX id isn't present
            else if rxChar == nil && (c.properties.contains(.write) || c.properties.contains(.writeWithoutResponse))
                        && !up.contains(txSuffix) { rxChar = c }
        }
        status = "GATT: \(chars.count) chars, notify=\(notifyChars.count), rx=\(rxChar != nil ? "yes" : "NO") — starting stream"
        // Auto-start shortly after discovery so packets flow without manual timing.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) { [weak self] in self?.startStream() }
    }
    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard let data = characteristic.value else { return }
        logPacket(characteristic.uuid.uuidString, data)
        decodeReading([UInt8](data))
    }

    /// Best-effort plain-language decode so the wearer sees a number, not hex — and
    /// it reveals WHICH byte the HR lands in. For a real-time-HR frame (0x69), scan
    /// the payload for a plausible bpm (40–200); otherwise show the raw payload head.
    private func decodeReading(_ b: [UInt8]) {
        guard b.count >= 7 else { return }
        let now = Date().timeIntervalSince1970
        if b[0] == 0x69 {                              // real-time reading frame (colmi R0x layout)
            // Diagnostic: total 0x69 stream rate (every frame, before the PPG filter).
            // If this is ~8 Hz while the usable PPG rate is ~2 Hz, most frames arrive with
            // no PPG in bytes 6-7; if BOTH are ~2 Hz, iOS has throttled the BLE link.
            allFrameTimes.append(now); allFrameTimes.removeAll { now - $0 > 3 }
            if allFrameTimes.count >= 2, let f = allFrameTimes.first, now - f > 0.2 {
                frameHz = Double(allFrameTimes.count - 1) / (now - f)
            }
            // byte2 = error code (0 = ok); bytes 6-7 (LE) = raw green-LED PPG. We use the
            // ring for LIVENESS ONLY — this ring's ~2 Hz BLE stream is too sparse to
            // recover an accurate bpm, so we don't report a heart-rate number.
            let err = b[2]
            let ppg = Int(b[6]) | (Int(b[7]) << 8)
            if ppg > 0 && ppg < 5000 {                 // keep the raw PPG (drop 0 / sync frames)
                ppgWindow.append(Double(ppg)); if ppgWindow.count > 24 { ppgWindow.removeFirst() }
            }
            // Live-pulse: the PPG oscillates on a live finger, flatlines when removed. This
            // is the liveness signal the presence gate uses — robust at any sample rate.
            var pulse = false
            if ppgWindow.count >= 8 {
                let mean = ppgWindow.reduce(0, +) / Double(ppgWindow.count)
                let osc = (ppgWindow.map { ($0 - mean) * ($0 - mean) }.reduce(0, +) / Double(ppgWindow.count)).squareRoot()
                pulse = osc > 3 && mean > 50
            }
            if pulse { lastHRTime = now }
            if pulse {
                reading = "LIVE PULSE ✓ · ppg \(ppg)"
            } else if err != 0 {
                reading = "measuring… keep the ring on your finger (err \(err))"
            } else {
                reading = "reading PPG… ppg \(ppg)"
            }
        } else if b[0] == R10.Command.accelStream.rawValue {   // accel triple (if the ring streams it)
            func i16(_ hi: UInt8, _ lo: UInt8) -> Double { Double(Int16(bitPattern: (UInt16(hi) << 8) | UInt16(lo))) }
            let g = 16384.0                             // ~±2g full-scale (STK8321) — refine against data
            let x = i16(b[1], b[2]) / g, y = i16(b[3], b[4]) / g, z = i16(b[5], b[6]) / g
            let cur = SIMD3(x, y, z)
            accelMean = accelMean == .zero ? cur : accelMean * 0.9 + cur * 0.1   // EMA = gravity/DC
            let dx = x - accelMean.x, dy = y - accelMean.y, dz = z - accelMean.z
            lastMotion = (dx*dx + dy*dy + dz*dz).squareRoot()                     // dynamic motion, g
            accelSamples.append((now, lastMotion)); accelSamples.removeAll { now - $0.t > 12 }
            accelFrameTimes.append(now); accelFrameTimes.removeAll { now - $0 > 3 }
            if accelFrameTimes.count >= 2, let f = accelFrameTimes.first, now - f > 0.2 {
                accelHz = Double(accelFrameTimes.count - 1) / (now - f)           // measure: does it stream, how fast?
            }
        }
        updateLiveness(now: now)
    }

    /// Real ring-liveness verdict from what the R10 actually gives: a fresh, valid
    /// pulse in the live stream means worn + measuring; a lost/absent stream means
    /// removed. Motion (if the accel streams) adds the on-body anti-removal check.
    /// The live-presence window for the session's ring `SignalSource`: the recent raw
    /// PPG bytes WHEN a live pulse is present, else EMPTY (fail-closed). Presence/timing
    /// only — never key material. Empty window -> `SignalSource.present == false` -> the
    /// enrol ceremony and ratchet gate closed (no pulse = not present).
    /// Whether the ring is currently streaming its accelerometer (the R10's accel stream is
    /// intermittent — the handshake tap bind needs it).
    var isStreamingAccel: Bool { !accelSamples.isEmpty }

    /// Ring-accel tap onset times over the last `windowS` seconds — threshold-cross peaks on
    /// the on-body motion, for the enrolment handshake bind. Empty if the ring isn't streaming
    /// accel.
    func ringTapTimes(windowS: Double, threshold: Double = 0.15, refractoryS: Double = 0.15) -> [Double] {
        let now = Date().timeIntervalSince1970
        let recent = accelSamples.filter { now - $0.t <= windowS }
        guard recent.count > 1 else { return [] }
        var taps: [Double] = []; var last = -1e9
        for i in 1..<recent.count where recent[i].mag >= threshold && recent[i - 1].mag < threshold && (recent[i].t - last) >= refractoryS {
            taps.append(recent[i].t); last = recent[i].t
        }
        return taps
    }

    func presenceWindow() -> Data {
        guard pulsePresent else { return Data() }
        return Data(ppgWindow.suffix(8).flatMap { v -> [UInt8] in
            let i = Int(v); return [UInt8(i & 0xff), UInt8((i >> 8) & 0xff)]
        })
    }

    private func updateLiveness(now: TimeInterval) {
        let pulseFresh = (now - lastHRTime) < 5     // a live PPG oscillation seen recently
        pulsePresent = pulseFresh                   // publish for the presence gate (fail-closed when flat)
        if pulseFresh {
            liveness = "PRESENT ✓ · live pulse"
                     + (lastMotion > 0 ? " · motion \(String(format: "%.3f", lastMotion))g" : "")
        } else {
            liveness = "absent — no live pulse (ring off skin / not measuring)"
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        if let e = error { event("write error: \(e.localizedDescription)") }
    }
}

/// The R10 as a `Wearable`: a pulse-only sensor ring. Capabilities are DERIVED FROM WHAT IT
/// ACTUALLY STREAMS right now (pulse always; on-body/high-rate IMU only if the accel stream
/// is live and fast enough) — never asserted. It has NO secure element, so it cannot hold
/// resumption codes: `resumptionCode` returns nil and the caller falls back to pulse-based
/// resume. A future nRF5340 ring is a different `Wearable` with `.secureElement` set.
extension RingProbe: Wearable {
    var deviceName: String { connectedName }
    var isConnected: Bool { !connectedName.isEmpty }

    var capabilities: WearableCapabilities {
        var caps: WearableCapabilities = [.pulse]           // it does PPG → liveness
        if isStreamingAccel {
            caps.insert(.onBodyMotion)
            if accelHz >= 20 { caps.insert(.highRateIMU) }  // fast enough for sharp taps
        }
        return caps                                          // never .secureElement (dumb ring)
    }

    func tapTimes(windowS: Double) -> [Double] { ringTapTimes(windowS: windowS) }
    func resumptionCode(counter: Int) -> Data? { nil }       // no secure element on the R10
}
