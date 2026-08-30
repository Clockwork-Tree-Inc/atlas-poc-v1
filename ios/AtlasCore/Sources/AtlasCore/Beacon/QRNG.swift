import Foundation

/// Presence-fired Server-QRNG — the Living Key (LK) stand-in (§3.1, §3.2).
/// Mirrors `backend/atlas/beacon/qrng.py`. On the kit the QRNG lives on the Mac;
/// the phone consumes its timed draw.
///
/// CORRECTED principle (§2.3): timing TIMES the firing; it NEVER enters the value.
/// The LK value is a CLEAN QRNG output — `sha256("atlas/qrng/value", core)`. NEITHER
/// the inter-arrival timing digest NOR the external-drand `anchor` is mixed into the
/// value bytes; the timing only sets WHEN the QRNG next fires (`nextSamplingOffset`),
/// and the `anchor` is recorded for bootstrap / defence-in-depth only. The aggregator's
/// public epoch beacon (`EpochBeacon`) is built ON TOP of these draws — it is the epoch
/// key, not drand. `timingCommitment` is retained for scheduling/audit, NOT as key material.
public struct ArrivalTiming {
    public var timestamps: [TimeInterval]
    public init(timestamps: [TimeInterval] = []) { self.timestamps = timestamps }

    public func interArrivals() -> [TimeInterval] {
        let ts = timestamps.sorted()
        return zip(ts, ts.dropFirst()).map { $1 - $0 }
    }
    public func digest() -> Data {
        var buf = Data()
        for d in interArrivals() {
            var ms = Int64((d * 1000).rounded()).bigEndian
            withUnsafeBytes(of: &ms) { buf.append(contentsOf: $0) }
        }
        return Primitives.H(Data("atlas/interarrival".utf8), buf)
    }
}

public struct TimedDraw {
    public let anchor: Data          // OPTIONAL external-drand round, recorded for bootstrap /
                                     // defence-in-depth ONLY — never folded into `randomness`
    public let randomness: Data      // the entropy each device folds into its session key (CLEAN QRNG)
    public let timingCommitment: Data
    public let nextSamplingOffset: TimeInterval
}

public final class ServerQRNG {
    public let basePeriod: TimeInterval
    public init(basePeriod: TimeInterval = 3) { self.basePeriod = basePeriod }

    public func fire(arrival: ArrivalTiming, anchor: Data = Data()) -> TimedDraw {
        let core = Primitives.randomBytes(32)        // fresh entropy core
        let timing = arrival.digest()
        // THE PRINCIPLE (§2.3, corrected): timing TIMES the firing and the drand
        // anchor only ANNOTATES it; NEITHER enters the value. The LK value is a
        // CLEAN QRNG output (core alone). The aggregate arrival timing's only role
        // is to drive WHEN the QRNG fires (the next-sampling schedule below).
        let randomness = Primitives.sha256(Data("atlas/qrng/value".utf8), core)
        // The arrival timing "times the next sampling": jitter the next firing
        // window by the aggregate arrival pattern (a schedule input, not a value).
        let jitter = (Double(timing.first ?? 0) / 255.0) * basePeriod
        return TimedDraw(anchor: anchor, randomness: randomness,
                         timingCommitment: timing,   // retained for schedule/audit, NOT in the value
                         nextSamplingOffset: basePeriod + jitter)
    }
}
