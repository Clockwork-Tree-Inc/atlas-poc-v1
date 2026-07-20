import Foundation

/// Bayesian liveness gate and PoLE state (§5.2). Mirrors
/// `backend/atlas/liveness/bayes.py`.
///
/// P(L|S) = P(S|L)·P(L) / [ P(S|L)·P(L) + P(S|¬L)·(1−P(L)) ],  P(L) ~ Beta(a0,b0)
/// PoLE_state = H( P(L|S) || sensor_digest || epoch )   [no ring_SE_sig at Tier 3]
public struct PoLEState {
    public let pLive: Double
    public let stateDigest: Data
    public let drandRound: Data
    public let operate: Bool
}

public final class LivenessGate {
    private var a: Double
    private var b: Double
    public let piStar: Double
    public init(a0: Double = Params.livenessPriorA0, b0: Double = Params.livenessPriorB0,
                piStar: Double = Params.piStar) {
        self.a = a0; self.b = b0; self.piStar = piStar
    }
    public var pLive: Double { a / (a + b) }

    @discardableResult
    public func update(pSGivenLive: Double, pSGivenNotLive: Double) -> Double {
        let pl = pLive
        let num = pSGivenLive * pl
        let den = num + pSGivenNotLive * (1 - pl)
        let post = den > 0 ? num / den : 0
        a += post
        b += (1 - post)
        return post
    }

    public func state(sensorDigest: Data, drandRound: Data) -> PoLEState {
        let p = pLive
        var pbe = p.bitPattern.bigEndian
        let pBytes = withUnsafeBytes(of: &pbe) { Data($0) }
        let digest = Primitives.H(Data("atlas/pole".utf8), pBytes, sensorDigest, drandRound)
        return PoLEState(pLive: p, stateDigest: digest, drandRound: drandRound, operate: p >= piStar)
    }
}
