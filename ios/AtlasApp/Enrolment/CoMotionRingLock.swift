import Foundation
import AtlasCore

/// Co-motion ring-lock at enrolment — accelerometer-only (§6).
///
/// With the ring on the finger, the same finger taps the phone. The wallet
/// issues a QRNG-fresh challenge tap pattern; the user taps it; the ring's
/// accelerometer (STK8321, no gyroscope) records the same sequence
/// simultaneously. Correlating the ring's motion peaks against the phone's
/// registered tap events binds the ring to the verified person.
///
/// Tier-1 uses a richer 6-axis IMU; the R10 uses the accelerometer alone —
/// coarser but sufficient for the click correlation (§6).
public struct CoMotionRingLock {
    /// Matching tolerance — reuses the recognition window epsilon (§3.2 #4).
    public let epsilon: TimeInterval = Params.recognitionWindowEpsilon

    /// Issue a fresh challenge: N taps with QRNG-derived inter-tap gaps.
    public func issueChallenge(taps: Int = 5) -> [TimeInterval] {
        var gaps: [TimeInterval] = []
        let draw = Primitives.randomBytes(taps)
        var t: TimeInterval = 0
        for i in 0..<taps {
            // 0.3–0.8s gaps, QRNG-derived so the pattern can't be pre-recorded.
            t += 0.3 + Double(draw[draw.startIndex + i]) / 255.0 * 0.5
            gaps.append(t)
        }
        return gaps
    }

    /// Correlate the phone's registered tap event times with the ring's
    /// accelerometer peak times. Returns a score in [0,1]: the fraction of
    /// challenge taps matched within epsilon, on both channels.
    public func correlate(phoneTapTimes: [TimeInterval], ringPeakTimes: [TimeInterval]) -> Double {
        guard !phoneTapTimes.isEmpty else { return 0 }
        var matched = 0
        var used = Array(repeating: false, count: ringPeakTimes.count)
        for pt in phoneTapTimes {
            if let j = ringPeakTimes.indices.first(where: { !used[$0] && abs(ringPeakTimes[$0] - pt) <= epsilon }) {
                used[j] = true; matched += 1
            }
        }
        return Double(matched) / Double(phoneTapTimes.count)
    }

    /// The lock binds if enough taps line up on both channels.
    public func isLocked(phoneTapTimes: [TimeInterval], ringPeakTimes: [TimeInterval],
                         threshold: Double = 0.8) -> Bool {
        correlate(phoneTapTimes: phoneTapTimes, ringPeakTimes: ringPeakTimes) >= threshold
    }

    /// Extract accelerometer peak times from R10 readings (simple magnitude
    /// threshold on the streamed accel vector).
    public static func peakTimes(from samples: [(time: TimeInterval, reading: R10.Reading)],
                                 magnitudeThreshold: Double = 1500) -> [TimeInterval] {
        samples.compactMap { item in
            guard let a = item.reading.accel else { return nil }
            let mag = sqrt(Double(a.x) * Double(a.x) + Double(a.y) * Double(a.y) + Double(a.z) * Double(a.z))
            return mag >= magnitudeThreshold ? item.time : nil
        }
    }
}
