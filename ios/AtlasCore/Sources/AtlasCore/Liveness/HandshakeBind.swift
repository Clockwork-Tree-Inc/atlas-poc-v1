import Foundation

/// Enrolment handshake-bind verifier. Mirrors `backend/atlas/liveness/handshake_bind.py`.
///
/// At enrolment the phone shows a RANDOM number N. Holding the phone in the same hand that
/// wears the ring, the user taps the ring on the phone N times while Face ID authenticates.
/// Each tap is a sharp impulse both IMUs (and the mic) register at the same instant, binding
/// WHO (Face ID) + ALIVE (pulse) + SAME-BODY (co-occurring taps) to one moment. The random N
/// is an unreplayable challenge. Measures to gate — never a key/value.

/// Impulse onset times (seconds) from a 1-D motion-magnitude (or audio-energy) signal:
/// upward threshold crossings, with a refractory gap so one tap isn't double-counted.
public func detectTaps(_ signal: [Double], fs: Double, threshold: Double,
                       refractoryS: Double = 0.12) -> [Double] {
    var times: [Double] = []
    var last = -1e9
    let dt = 1.0 / fs
    guard signal.count > 1 else { return times }
    for i in 1..<signal.count {
        let t = Double(i) * dt
        if signal[i] >= threshold && signal[i - 1] < threshold && (t - last) >= refractoryS {
            times.append(t); last = t
        }
    }
    return times
}

/// Bijection: every impulse in `a` has a distinct partner in `b` within `tolS`.
func handshakeAligned(_ a: [Double], _ b: [Double], tolS: Double) -> Bool {
    guard a.count == b.count else { return false }
    var used = [Bool](repeating: false, count: b.count)
    for ta in a {
        var hit = -1
        for j in 0..<b.count where !used[j] && abs(ta - b[j]) <= tolS { hit = j; break }
        if hit < 0 { return false }
        used[hit] = true
    }
    return true
}

/// True iff the random-N tap challenge was met live and co-located: exactly `requestedN`
/// taps on the phone AND the ring (and mic, if given), each phone tap co-occurring with a
/// ring/mic tap within `alignTolS`, all within ±`windowS` of the Face-ID instant. Fail-closed.
public func verifyHandshake(phoneTaps: [Double], ringTaps: [Double], requestedN: Int,
                            faceIDAtS: Double, micTaps: [Double]? = nil,
                            windowS: Double = 6.0, alignTolS: Double = 0.08) -> Bool {
    guard requestedN > 0 else { return false }
    guard phoneTaps.count == requestedN, ringTaps.count == requestedN else { return false }
    let lo = faceIDAtS - windowS, hi = faceIDAtS + windowS
    if (phoneTaps + ringTaps).contains(where: { !($0 >= lo && $0 <= hi) }) { return false }
    guard handshakeAligned(phoneTaps, ringTaps, tolS: alignTolS) else { return false }
    if let mic = micTaps {
        guard mic.count == requestedN, handshakeAligned(phoneTaps, mic, tolS: alignTolS) else { return false }
    }
    return true
}
