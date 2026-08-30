import Foundation

/// Independent per-device ratchet cadence — 10s ± BIOLOGICAL jitter (§5.3, §16).
/// Mirrors `backend/atlas/session/cadence.py`.
///
/// Every clock = a regular base period + biological jitter. The device ratchet's
/// jitter within [nominal ± jitter] is derived from the enrolled ring's live
/// sensor signal (the same stream that times the PoLE draw) — NOT from an RNG,
/// NOT a fixed schedule.
///
/// THE PRINCIPLE (§2.3): the biological signal determines a SCHEDULE offset (WHEN
/// the next tick fires) — a timing value. It is NEVER folded into key material;
/// the clock is a scheduler of WHEN, never a source of key bytes.
public enum CadenceError: Error, Equatable {
    case jitterNegative                 // jitter must be non-negative
    case jitterNotSmallerThanNominal    // jitter must be smaller than the nominal period
    case bioSignalRequired              // biological signal required to time the clock
}

public final class RatchetClock {
    public let nominalS: Double
    public let jitterS: Double
    private var lastIntervalS: Double?

    public init(nominalS: Double = Params.ratchetNominalS,
                jitterS: Double = Params.ratchetJitterS) throws {
        if jitterS < 0 { throw CadenceError.jitterNegative }
        if jitterS >= nominalS { throw CadenceError.jitterNotSmallerThanNominal }
        self.nominalS = nominalS
        self.jitterS = jitterS
        self.lastIntervalS = nil
    }

    /// Time the next interval within [nominal ± jitter] from the enrolled ring's
    /// live signal. `bioSignal` is a fresh sensor sample; a sample byte maps to a
    /// schedule offset in the jitter band. This is a WHEN — it is NOT folded into
    /// any key and carries no key material.
    @discardableResult
    public func nextInterval(bioSignal: Data) throws -> Double {
        guard let first = bioSignal.first else { throw CadenceError.bioSignalRequired }
        let frac = Double(first) / 255.0                                    // live sample -> [0,1]
        let intervalS = (nominalS - jitterS) + frac * (2.0 * jitterS)
        lastIntervalS = intervalS
        return intervalS
    }

    public var lastInterval: Double? { lastIntervalS }
}
