import Foundation

/// Presence-fired Server-QRNG — the Living Key (LK) stand-in (§3.1, §3.2).
/// Mirrors `backend/atlas/beacon/qrng.py`. On the kit the QRNG lives on the Mac;
/// the phone consumes its timed draw.
///
/// CORRECTED principle (§2.3): timing TIMES the firing; it NEVER enters the value.
/// The LK value is a CLEAN QRNG output — `sha256("atlas/qrng/value", core, drandRound)`.
/// The inter-arrival timing digest is NOT mixed into the value bytes; it only sets
/// WHEN the QRNG next fires (`nextSamplingOffset`). `timingCommitment` is retained
/// on the draw for scheduling/audit, NOT as key material.
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
    public let drandRound: Data
    public let randomness: Data
    public let timingCommitment: Data
    public let nextSamplingOffset: TimeInterval
}

public final class ServerQRNG {
    public let basePeriod: TimeInterval
    public init(basePeriod: TimeInterval = 3) { self.basePeriod = basePeriod }

    public func fire(arrival: ArrivalTiming, drandRound: Data) -> TimedDraw {
        let core = Primitives.randomBytes(32)        // fresh entropy core
        let timing = arrival.digest()
        // THE PRINCIPLE (§2.3, corrected): timing TIMES the firing; it does NOT
        // enter the value. The LK value is a CLEAN QRNG output (core), never a
        // function of the timing digest. The aggregate arrival timing's only role
        // is to drive WHEN the QRNG fires (the next-sampling schedule below).
        let randomness = Primitives.sha256(Data("atlas/qrng/value".utf8), core, drandRound)
        // The arrival timing "times the next sampling": jitter the next firing
        // window by the aggregate arrival pattern (a schedule input, not a value).
        let jitter = (Double(timing.first ?? 0) / 255.0) * basePeriod
        return TimedDraw(drandRound: drandRound, randomness: randomness,
                         timingCommitment: timing,   // retained for schedule/audit, NOT in the value
                         nextSamplingOffset: basePeriod + jitter)
    }
}
