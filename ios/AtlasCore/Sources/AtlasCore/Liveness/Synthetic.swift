import Foundation

/// Synthetic presence + spoof streams (§5.1, §11). Mirrors
/// `backend/atlas/liveness/synthetic.py`. Models the R10's real sensors:
/// PPG (HR/HRV/SpO2) + 3-axis accelerometer. A live human shows HR in range,
/// genuine HRV, and micro-movement; a screen/replay spoof shows flat HRV and
/// sub-baseline stillness. Used for preview/tests, not cross-wire interop.
public struct SensorSample {
    public let hr: Double
    public let hrvMS: Double
    public let spo2: Double
    public let accelMag: Double
    public init(hr: Double, hrvMS: Double, spo2: Double, accelMag: Double) {
        self.hr = hr; self.hrvMS = hrvMS; self.spo2 = spo2; self.accelMag = accelMag
    }
    public func digest() -> Data {
        Primitives.H(Data("atlas/sensor".utf8),
                     Data(String(format: "%.2f|%.2f|%.1f|%.4f", hr, hrvMS, spo2, accelMag).utf8))
    }
}

public enum Synthetic {
    static let hrMin = 48.0, hrMax = 110.0
    static let hrvLive = 45.0
    static let microMotionBaseline = 0.012

    /// Heuristic (P(S|L), P(S|¬L)) for one sample.
    public static func likelihood(_ s: SensorSample) -> (Double, Double) {
        let hrOK = s.hr >= hrMin && s.hr <= hrMax
        let hrvOK = s.hrvMS >= 15
        let motionOK = s.accelMag >= microMotionBaseline
        let spo2OK = s.spo2 >= 90 && s.spo2 <= 100
        let score = [hrOK, hrvOK, motionOK, spo2OK].filter { $0 }.count
        let live = [0.05, 0.2, 0.5, 0.85, 0.97][score]
        let notLive = [0.97, 0.85, 0.5, 0.2, 0.05][score]
        return (live, notLive)
    }

    /// Tiny deterministic PRNG so previews/tests are reproducible.
    struct LCG { var s: UInt64; mutating func next() -> Double {
        s = s &* 6364136223846793005 &+ 1442695040888963407
        return Double(s >> 11) / Double(1 << 53)
    } }

    public static func liveStream(_ n: Int = 40, seed: UInt64 = 1) -> [(SensorSample, (Double, Double))] {
        var rng = LCG(s: seed); var hr = 68.0; var out: [(SensorSample, (Double, Double))] = []
        for _ in 0..<n {
            hr += (rng.next() - 0.5) * 5
            hr = min(max(hr, hrMin + 3), hrMax - 3)
            let s = SensorSample(hr: hr, hrvMS: hrvLive + (rng.next() - 0.5) * 24,
                                 spo2: 97.5 + (rng.next() - 0.5) * 2.4,
                                 accelMag: microMotionBaseline + abs((rng.next() - 0.5) * 0.02))
            out.append((s, likelihood(s)))
        }
        return out
    }

    public static func spoofStream(_ n: Int = 40, seed: UInt64 = 2) -> [(SensorSample, (Double, Double))] {
        var rng = LCG(s: seed); var out: [(SensorSample, (Double, Double))] = []
        for _ in 0..<n {
            let s = SensorSample(hr: 72 + (rng.next() - 0.5) * 0.6, hrvMS: 3 + (rng.next() - 0.5) * 2,
                                 spo2: 98, accelMag: 0.001 + rng.next() * 0.002)
            out.append((s, likelihood(s)))
        }
        return out
    }
}
