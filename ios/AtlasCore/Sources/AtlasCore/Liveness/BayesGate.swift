import Foundation

/// Bayesian liveness gate and PoLE state (§5.2). Mirrors
/// `backend/atlas/liveness/bayes.py`.
///
/// P(L|S) = P(S|L)·P(L) / [ P(S|L)·P(L) + P(S|¬L)·(1−P(L)) ],  P(L) ~ Beta(a0,b0)
/// PoLE_state = H( P(L|S) || sensor_digest || epoch )   [no ring_SE_sig at Tier 3]
public struct PoLEState {
    public let pLive: Double
    public let stateDigest: Data
    public let epochRound: Data
    public let operate: Bool
}

public final class LivenessGate {
    private var a: Double
    private var b: Double
    public let piStar: Double
    // M7 hardening: bound single-sample influence + require sustained evidence.
    private let minSamples: Int
    private let clampEps: Double
    private var n: Int = 0
    public init(a0: Double = Params.livenessPriorA0, b0: Double = Params.livenessPriorB0,
                piStar: Double = Params.piStar, minSamples: Int = Params.livenessMinSamples,
                clampEps: Double = Params.livenessLikClampEps) {
        self.a = a0; self.b = b0; self.piStar = piStar
        self.minSamples = minSamples; self.clampEps = clampEps
    }
    public var pLive: Double { a / (a + b) }

    /// M7 hardening: each per-sample likelihood is clamped into [eps, 1-eps] so no single
    /// crafted sample (e.g. P(S|¬L)->0) can slam the posterior to ~1 in one step. The clamp
    /// is below every legitimate stream's minimum, so it is a no-op for real signals.
    @discardableResult
    public func update(pSGivenLive: Double, pSGivenNotLive: Double) -> Double {
        let psl = min(max(pSGivenLive, clampEps), 1 - clampEps)
        let psnl = min(max(pSGivenNotLive, clampEps), 1 - clampEps)
        let pl = pLive
        let num = psl * pl
        let den = num + psnl * (1 - pl)
        let post = den > 0 ? num / den : 0
        a += post
        b += (1 - post)
        n += 1
        return post
    }

    public func state(sensorDigest: Data, epochRound: Data) -> PoLEState {
        let p = pLive
        var pbe = p.bitPattern.bigEndian
        let pBytes = withUnsafeBytes(of: &pbe) { Data($0) }
        let digest = Primitives.H(Data("atlas/pole".utf8), pBytes, sensorDigest, epochRound)
        // M7 hardening: require sustained evidence — a single (or too-few) sample(s)
        // cannot trip liveness even if p momentarily clears piStar.
        let operate = p >= piStar && n >= minSamples
        return PoLEState(pLive: p, stateDigest: digest, epochRound: epochRound, operate: operate)
    }
}
