import Foundation

/// Replays a RECORDED device-motion stream — e.g. the MotionSense dataset (24 iPhones,
/// Core Motion @ 50 Hz: `mmalekzadeh/motion-sense`) — through the `SignalSource` seam, so the
/// phone-ambient roles can be exercised on REAL human motion with no physical device. Test /
/// simulation source only.
///
/// SCOPE — what the phone-ambient window is FOR: it HARVESTS AS MUCH SENSOR ENTROPY as
/// possible per tick to RUN THE ENGINE (the PoLE/ratchet timing + gating). It is NOT a
/// presence or liveness detector — the phone does not detect human presence after enrolment;
/// continuous presence/liveness is the WEARABLE's role (ring/SE + high-frequency sensors). And
/// per the load-bearing invariant, this window TIMES/GATES the engine but is NEVER folded into
/// a key/value — the value stays clean QRNG. So the meaningful quantity here is the ENTROPY /
/// change captured per window; the `present`/change flag is just "the window carried fresh
/// entropy (vs a frozen/replayed feed with none)".
///
/// Each row's `userAcceleration` + `rotationRate` magnitudes are packed into the SAME
/// fused-window byte layout `AmbientSensorSource` emits, then wrapped in
/// `ChangeDetectingSignalSource` — so the identical change / entropy telemetry runs: a live
/// changing stream yields entropy; a frozen/looped window yields none. Magnetometer /
/// barometer / mic channels are absent in the dataset and packed as 0 (accel + gyro carry it).
public final class ReplaySignalSource {
    public struct Row {
        public let accel: Double   // |userAcceleration|
        public let gyro: Double    // |rotationRate|
        public init(accel: Double, gyro: Double) { self.accel = accel; self.gyro = gyro }
    }

    private let rows: [Row]
    private var i = 0
    public var count: Int { rows.count }

    public init(rows: [Row]) { self.rows = rows }

    /// Parse a MotionSense `A_DeviceMotion_data/*/sub_*.csv` (a header naming
    /// `userAcceleration.{x,y,z}` + `rotationRate.{x,y,z}`; extra columns are ignored),
    /// computing each row's magnitudes. Column order/count is taken from the header.
    public convenience init(motionSenseCSV text: String) {
        let lines = text.split(whereSeparator: \.isNewline)
        guard let header = lines.first else { self.init(rows: []); return }
        let cols = header.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
        func idx(_ name: String) -> Int? { cols.firstIndex(of: name) }
        guard let ax = idx("userAcceleration.x"), let ay = idx("userAcceleration.y"), let az = idx("userAcceleration.z"),
              let gx = idx("rotationRate.x"), let gy = idx("rotationRate.y"), let gz = idx("rotationRate.z") else {
            self.init(rows: []); return
        }
        let need = [ax, ay, az, gx, gy, gz].max()!
        var out: [Row] = []
        for line in lines.dropFirst() {
            let f = line.split(separator: ",", omittingEmptySubsequences: false).map { Double($0) ?? 0 }
            guard f.count > need else { continue }
            let a = (f[ax]*f[ax] + f[ay]*f[ay] + f[az]*f[az]).squareRoot()
            let g = (f[gx]*f[gx] + f[gy]*f[gy] + f[gz]*f[gz]).squareRoot()
            out.append(Row(accel: a, gyro: g))
        }
        self.init(rows: out)
    }

    private func byte(_ x: Double, _ scale: Double) -> UInt8 { UInt8(min(max(x * scale, 0), 255)) }

    /// The next fused window (advances through the stream; loops at the end). Matches the
    /// `AmbientSensorSource` byte layout — accel/gyro carry signal, mag/baro/mic are 0.
    public func nextWindow() -> Data {
        guard !rows.isEmpty else { return Data() }
        let r = rows[i % rows.count]; i += 1
        return Data([byte(r.accel, 255), byte(r.gyro, 64), 0, 0, 0,
                     byte(r.accel, 2048), byte(r.gyro, 512), 0])
    }

    /// A `SignalSource` over this replay stream — identical change/presence logic as ambient.
    public func asSignalSource() -> SignalSource {
        ChangeDetectingSignalSource(kind: "replay", simulated: true,
                                    channels: ["replay-accel", "replay-gyro"], liveFloor: 2) { [weak self] in
            self?.nextWindow() ?? Data()
        }
    }
}
