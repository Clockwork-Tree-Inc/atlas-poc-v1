import Foundation

/// GBSS entropy vector — structured liveness/context entropy (Math Spec v1.4).
/// Mirrors `backend/atlas/liveness/gbss.py`.
///
///   hI = HRV/PPG/GSR (involuntary biomechanical) — RING (deferred; nil on phone)
///   sI = motion-variance (IMU) — phone
///   mI = micro-interaction (touch/keystroke/voice) — phone partial
///   cI = contextual/environmental (ambient) — phone
///
/// Each channel is scored by the entropy operators into a density in [0,1], then
/// aggregated into a per-window liveness density that feeds the PoLE gate. On the
/// phone hI is nil (ring-deferred) and the density covers only present channels.
///
/// INVARIANT: densities are MEASUREMENTS that only gate/time — never a key/value.
public struct EntropyVector {
    public let sI: Double
    public let cI: Double
    public let mI: Double?
    public let hI: Double?

    public init(sI: Double, cI: Double, mI: Double? = nil, hI: Double? = nil) {
        self.sI = sI; self.cI = cI; self.mI = mI; self.hI = hI
    }

    public func present() -> [String: Double] {
        var out: [String: Double] = ["s_i": sI, "c_i": cI]
        if let mI { out["m_i"] = mI }
        if let hI { out["h_i"] = hI }
        return out
    }

    public var ringDeferred: Bool { hI == nil }

    /// Aggregate liveness density over the PRESENT channels (mean). When the ring
    /// lands, hI simply raises coverage — the shape is unchanged.
    public func density() -> Double {
        let vals = Array(present().values)
        return vals.isEmpty ? 0.0 : vals.reduce(0, +) / Double(vals.count)
    }
}

public enum GBSS {
    /// Density below this reads as degenerate (constant / replay / low diversity)
    /// -> strong not-live. Wants on-device tuning.
    public static let densityFloor = 0.15

    /// Score one channel's liveness density in [0,1] from its raw samples: a symbol
    /// sequence -> normalized Shannon + Lempel-Ziv; a waveform -> spectral entropy.
    public static func channelDensity(waveform: [Double]? = nil, symbols: [Data]? = nil) -> Double {
        var scores: [Double] = []
        if let symbols, !symbols.isEmpty {
            let (shannon, _) = Entropy.distributionEntropies(symbols)
            let maxBits = symbols.count > 1 ? log2(Double(symbols.count)) : 1.0
            scores.append(maxBits > 0 ? min(shannon / maxBits, 1.0) : 0.0)
            let joined = symbols.reduce(Data()) { $0 + $1 }
            scores.append(min(Entropy.lempelZivComplexity(joined), 1.0))
        }
        if let waveform, waveform.count >= 4 {
            scores.append(Entropy.spectralEntropy(waveform))
        }
        return scores.isEmpty ? 0.0 : scores.reduce(0, +) / Double(scores.count)
    }

    /// h_i — the INVOLUNTARY biomechanical entropy the R10 ring provides (the GBSS
    /// core the phone cannot produce). Mirrors Python `ring_h_i`. Blends HRV AMPLITUDE
    /// (healthy ~tens of ms; flat/spoof single-digit) with interval-series COMPLEXITY;
    /// low unless BOTH hold. A high-amplitude complex replay still needs the ring's
    /// own on-body anti-spoof (honest boundary).
    public static func ringHI(_ window: [SensorSample]) -> Double {
        if window.count < 4 { return 0.0 }
        let hrv = window.map { $0.hrvMS }
        let meanHRV = hrv.reduce(0, +) / Double(hrv.count)
        let amplitude = min(meanHRV / 40.0, 1.0)
        let q = window.map { Data([UInt8(min(max(Int($0.hrvMS), 0), 255))]) }
        let complexity = channelDensity(waveform: hrv, symbols: q)
        return 0.5 * amplitude + 0.5 * complexity
    }

    /// s_i from the ring's OWN IMU — on-wrist motion, more body-bound than the
    /// phone's. Mirrors Python `ring_s_i`. Same amplitude+complexity blend as h_i:
    /// a live wrist has real, complex micro-movement; a still/removed ring is
    /// near-zero flat motion (its tiny jitter must not read as live).
    public static func ringSI(_ window: [SensorSample]) -> Double {
        if window.count < 4 { return 0.0 }
        let accel = window.map { $0.accelMag }
        let meanAccel = accel.reduce(0, +) / Double(accel.count)
        let amplitude = min(meanAccel / 0.03, 1.0)
        let q = window.map { Data([UInt8(min(max(Int($0.accelMag * 1000), 0), 255))]) }
        let complexity = channelDensity(waveform: accel, symbols: q)
        return 0.5 * amplitude + 0.5 * complexity
    }

    /// Fuse phone motion with the ring's on-wrist motion (ring weighted higher, it is
    /// on-body). No ring -> the phone's s_i alone. Mirrors Python `fuse_motion_s_i`.
    public static func fuseMotionSI(_ phoneSI: Double, ringWindow: [SensorSample]?) -> Double {
        guard let ringWindow, ringWindow.count >= 4 else { return phoneSI }
        return 0.6 * ringSI(ringWindow) + 0.4 * phoneSI
    }

    /// Build the GBSS vector from the ring when present: h_i from HRV (the involuntary
    /// core) AND s_i FUSED with the ring's own IMU (on-wrist motion). Ring absent ->
    /// h_i deferred (nil) and s_i is the phone's alone.
    public static func entropyVectorWithRing(sI: Double, cI: Double, mI: Double? = nil,
                                             ringWindow: [SensorSample]? = nil) -> EntropyVector {
        let h: Double? = (ringWindow != nil && ringWindow!.count >= 4) ? ringHI(ringWindow!) : nil
        return EntropyVector(sI: fuseMotionSI(sI, ringWindow: ringWindow), cI: cI, mI: mI, hI: h)
    }

    /// Map a GBSS vector's density to Bayesian (live, notLive) for the PoLE gate.
    public static func livenessLikelihoods(_ v: EntropyVector,
                                           densityFloor: Double = densityFloor) -> (live: Double, notLive: Double) {
        let d = v.density()
        if d < densityFloor { return (0.02, 0.98) }
        let live = min(0.5 + d * 0.48, 0.98)
        return (live, 1.0 - live)
    }

    /// Fold per-window GBSS vectors through the Bayesian LivenessGate into a PoLE.
    public static func poleFromGBSS(_ vectors: [EntropyVector], drandRound: Data,
                                    sensorDigest: Data = Data("gbss".utf8)) -> PoLEState {
        let gate = LivenessGate()
        for v in vectors {
            let (psl, psnl) = livenessLikelihoods(v)
            gate.update(pSGivenLive: psl, pSGivenNotLive: psnl)
        }
        return gate.state(sensorDigest: sensorDigest, drandRound: drandRound)
    }
}
