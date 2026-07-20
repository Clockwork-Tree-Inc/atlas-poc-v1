import Foundation

/// Swappable live-signal source — the external physical timing/gating input.
/// Mirrors `backend/atlas/session/signal_source.py`.
///
/// THE ROLE (Locked Model §2.3, unchanged invariant): a live physical signal
/// TIMES the QRNG draws and GATES/advances the ratchet ("is the signal present
/// right now?"). It is NEVER folded into a key/value. "Biology times; QRNG values."
///
/// This makes the external signal a SWAPPABLE SOURCE so the pipeline is
/// source-agnostic:
///
///     pipeline  <--  SignalSource.sample() -> LiveSignalSample(timing, present)
///
///  * `AmbientSensorSource` (in the app layer, AtlasApp/Ambient) — the phone's
///    fused multimodal ambient stream TIMES and GATES. STAND-IN for the ring
///    (`simulated == true`). The pure core defines only the protocol + samples;
///    the hardware sensor reads live in the app target (CoreMotion/AVAudio).
///  * `RingSignalSource` — the R10 ring's streamed biological signal. DEFERRED
///    in this build; present only to prove the swap point. Ambient -> ring is a
///    SOURCE swap, no pipeline rewiring.
///
/// LOAD-BEARING INVARIANT (enforced by construction; parity-checked against
/// Python): `LiveSignalSample.timing` feeds ONLY scheduling — `RatchetClock
/// .nextInterval` and the PoLE fire moment. It must NEVER reach an HKDF/value.

public struct LiveSignalSample: Equatable, Sendable {
    /// A WHEN — drives the ratchet cadence + QRNG fire moment; never key material.
    public let timing: Data
    /// The live "signal present right now" gate.
    public let present: Bool
    /// "ambient" | "ring" | ...
    public let kind: String
    /// True = stand-in (not coherent living biology). Loud on purpose.
    public let simulated: Bool
    /// Contributing channels (for honest logging).
    public let channels: [String]
    // Liveness telemetry (measurements for gating only — NEVER value material):
    public let changedBits: Int?       // popcount(this XOR previous snapshot)
    public let entropyBits: Double?    // Shannon across snapshots (nil until warm)
    public let minEntropyBits: Double? // min-entropy across snapshots (the hard gate)

    public init(timing: Data, present: Bool, kind: String,
                simulated: Bool, channels: [String] = [],
                changedBits: Int? = nil, entropyBits: Double? = nil, minEntropyBits: Double? = nil) {
        self.timing = timing
        self.present = present
        self.kind = kind
        self.simulated = simulated
        self.channels = channels
        self.changedBits = changedBits
        self.entropyBits = entropyBits
        self.minEntropyBits = minEntropyBits
    }
}

public enum SignalSourceError: Error, Equatable {
    /// The requested source is not wired in this build (e.g. the deferred R10
    /// ring source under the AMBIENT_SIGNAL_SOURCE build).
    case unavailable(String)
}

/// A source of a live physical timing/gating signal. The pipeline consumes ONLY
/// this protocol, so ambient (now) and ring (later) are interchangeable.
public protocol SignalSource {
    var kind: String { get }
    var simulated: Bool { get }
    /// Return the current live sample. Called once per prospective ratchet tick
    /// to (a) time the interval and (b) test the presence gate.
    func sample() throws -> LiveSignalSample
}

/// The R10 ring's streamed biological continuity signal — the coherent-living-
/// biology anchor. Mirrors the Python `RingSignalSource`. Now WIRED: it consumes a
/// ring sampler (the real R10 on device, or an injected `SensorSample` stream in
/// tests) and produces the SAME `LiveSignalSample` the ambient source does — the
/// source swap the architecture promised, no pipeline rewiring.
///
/// `simulated = false` — the REAL coherent-biology anchor (that flag flips honestly
/// vs the ambient stand-in). A removed/absent ring (sampler -> nil) or an incoherent
/// pulse (flat HRV / spoof) reads as ABSENT -> gate closes (fail-closed): the
/// liveness-break signal ambient lacked. With NO sampler it THROWS (refuses to fake
/// biology). Biological signal times/gates — never a key/value.
public struct RingSignalSource: SignalSource {
    public let kind = "ring"
    public let simulated = false
    private let sampler: (() -> SensorSample?)?

    public init(sampler: (() -> SensorSample?)? = nil) { self.sampler = sampler }

    /// The ring's IMU also gates on-body presence: a worn ring has physiological
    /// micro-tremor; a removed/motionless ring reads near-zero. Below this it is not
    /// on a body (catches removal AND a replayed pulse fed to a still ring).
    static let removedAccel = 0.005

    /// A plausible LIVING pulse ON A BODY: HR in range, real beat-to-beat HRV, AND
    /// the IMU showing on-body micro-movement.
    static func coherent(_ s: SensorSample) -> Bool {
        s.hr >= 40 && s.hr <= 200 && s.hrvMS >= 10 && s.accelMag >= removedAccel
    }

    public func sample() throws -> LiveSignalSample {
        guard let sampler else {
            throw SignalSourceError.unavailable(
                "no ring wired — refusing to fake biology; inject a ring sampler "
                + "(real R10 on device, or a SensorSample stream in tests)")
        }
        guard let s = sampler(), RingSignalSource.coherent(s) else {
            return LiveSignalSample(timing: Data(), present: false, kind: kind, simulated: false)
        }
        // timing from beat-to-beat biological jitter (schedule only, never a value).
        let t = UInt8(((Int(s.hrvMS * 3 + s.hr) % 256) + 256) % 256)
        return LiveSignalSample(timing: Data([t]), present: true, kind: kind, simulated: false)
    }
}

/// A closure-backed source — lets the app inject the real fused-ambient reader
/// (or a deterministic sampler in tests) without the core depending on
/// CoreMotion/AVFoundation. The app's `AmbientSensorSource` produces the fused
/// window; the presence/timing derivation below matches the Python reference.
public struct ClosureSignalSource: SignalSource {
    public let kind: String
    public let simulated: Bool
    public let channels: [String]
    private let sampler: () -> Data
    private let liveFloor: Int

    public init(kind: String, simulated: Bool, channels: [String] = [],
                liveFloor: Int = 2, sampler: @escaping () -> Data) {
        self.kind = kind
        self.simulated = simulated
        self.channels = channels
        self.liveFloor = liveFloor
        self.sampler = sampler
    }

    public func sample() throws -> LiveSignalSample {
        let window = sampler()
        // Presence gate: a live ambient stream is not flatlined. Empty/near-zero
        // window -> "signal absent" -> gate closes (fail-closed).
        let liveBytes = window.reduce(0) { $0 + ($1 != 0 ? 1 : 0) }
        let present = liveBytes >= liveFloor
        // Timing byte: schedule offset from the fused window. TIMING ONLY — never
        // reaches a KDF (see PoLE.firePoLEValue / RatchetClock).
        let timing = window.isEmpty ? Data() : window.prefix(1)
        return LiveSignalSample(timing: Data(timing), present: present, kind: kind,
                                simulated: simulated, channels: channels)
    }
}

// MARK: - change-detection (ambient: change, not level). Mirrors the Python
// AmbientSensorSource. Each snapshot is XOR'd against the previous; entropy is
// measured ACROSS SNAPSHOTS (symbols). All of this only times/gates — never a value.

public enum AmbientChange {
    static let changeFloor = 1                 // a live sensor flips >= this many bits/tick
    static let timingWeights = [997, 631, 271, 4099, 5003, 211, 83, 149]
    static let entropyHistory = 16             // buffer of snapshots -> max entropy 4 bits
    static let entropyWarm = 4
    static let minEntropyFloorBits = 2.5       // hard gate (catches <=~5-frame loops)

    static func popcount(_ d: Data) -> Int { d.reduce(0) { $0 + $1.nonzeroBitCount } }

    /// Fold the XOR-delta into one well-spread schedule byte (0..255). Jitter is
    /// driven by CHANGE, never absolute level. Schedule only — never a value.
    static func spreadDelta(_ delta: Data) -> UInt8 {
        var mix = 0
        for (i, d) in delta.enumerated() { mix += Int(d) * timingWeights[i % timingWeights.count] }
        return UInt8(((mix % 256) + 256) % 256)
    }

    /// (Shannon, min-entropy) in bits over a sequence of snapshot symbols. Shannon
    /// = average unpredictability; min-entropy = -log2 max p (worst-case). Measured
    /// across whole snapshots so a bit-flipping replay loop still reads as few
    /// distinct symbols. Measurement only; never a value.
    static func distributionEntropies(_ symbols: [Data]) -> (shannon: Double, minEntropy: Double) {
        Entropy.distributionEntropies(symbols)      // canonical operator (Liveness/Entropy.swift)
    }
}

/// Stateful ambient source that derives PRESENCE + TIMING from how each snapshot
/// CHANGES, not its absolute level (mirrors the Python AmbientSensorSource). XOR vs
/// the previous snapshot (raw — noise and everything) kills a frozen/replayed
/// frame; entropy across snapshots (Shannon reported, min-entropy hard-gates once
/// the buffer is full) kills a short replay loop. First tick bootstraps on window
/// liveness. A `final class` because it holds the prev/history state.
public final class ChangeDetectingSignalSource: SignalSource {
    public let kind: String
    public let simulated: Bool
    public let channels: [String]
    private let sampler: () -> Data
    private let liveFloor: Int
    private var prev: Data?
    private var history: [Data] = []

    public init(kind: String, simulated: Bool, channels: [String] = [],
                liveFloor: Int = 2, sampler: @escaping () -> Data) {
        self.kind = kind; self.simulated = simulated; self.channels = channels
        self.liveFloor = liveFloor; self.sampler = sampler
    }

    public func sample() throws -> LiveSignalSample {
        let window = sampler()
        let liveBytes = window.reduce(0) { $0 + ($1 != 0 ? 1 : 0) }
        let windowLive = liveBytes >= liveFloor
        let previous = prev
        prev = window
        if !window.isEmpty {
            history.append(window)
            if history.count > AmbientChange.entropyHistory { history.removeFirst() }
        }

        // BOOTSTRAP: first comparable tick has no previous snapshot.
        guard let previous, previous.count == window.count, !window.isEmpty else {
            let timing = window.isEmpty ? Data() : Data(window.prefix(1))
            return LiveSignalSample(timing: timing, present: windowLive, kind: kind,
                                    simulated: simulated, channels: channels)
        }

        // CHANGE-DETECTION: XOR vs the previous snapshot (raw). Baseline cancels;
        // a frozen/replayed identical snapshot flips ZERO -> not present.
        let delta = Data(zip(window, previous).map { $0 ^ $1 })
        let changed = AmbientChange.popcount(delta)

        // Entropy across snapshots: Shannon (reported) + min-entropy (hard gate at
        // full buffer -> stable threshold; a partial window would false-fail noise).
        let warm = history.count >= AmbientChange.entropyWarm
        var shannon: Double? = nil, minEntropy: Double? = nil
        if warm {
            let e = AmbientChange.distributionEntropies(history)
            shannon = e.shannon; minEntropy = e.minEntropy
        }
        let full = history.count == AmbientChange.entropyHistory
        let entropyOK = (full && minEntropy != nil) ? (minEntropy! >= AmbientChange.minEntropyFloorBits) : true

        let present = windowLive && changed >= AmbientChange.changeFloor && entropyOK
        return LiveSignalSample(timing: Data([AmbientChange.spreadDelta(delta)]), present: present,
                                kind: kind, simulated: simulated, channels: channels,
                                changedBits: changed, entropyBits: shannon, minEntropyBits: minEntropy)
    }
}

/// Map one ambient sample's CHANGE + entropy telemetry to Bayesian
/// (live, notLive) likelihoods for the LivenessGate — so the REAL sensed change
/// DRIVES liveness (not synthetic data). Mirrors `ambient_liveness_likelihoods`.
/// Keys off `present` for the degenerate decision so it inherits the full-buffer
/// entropy logic (a small warm-up buffer must not read genuine noise as dead).
/// Evidence only; never a value.
public func ambientLivenessLikelihoods(_ sample: LiveSignalSample,
                                       windowBits: Int = 64) -> (live: Double, notLive: Double) {
    guard let changed = sample.changedBits else { return (0.5, 0.5) }   // bootstrap: neutral
    if !sample.present { return (0.02, 0.98) }                          // frozen / looped -> not-live
    let frac = Double(changed) / Double(windowBits)                     // ~0.5 noise, 0 frozen
    let live = min(0.5 + frac, 0.98)
    return (live, 1.0 - live)
}

/// Fold `ticks` ambient samples through a Bayesian LivenessGate into a PoLE, so the
/// PoLE liveness reflects the REAL ambient change. Mirrors `pole_from_ambient`. The
/// source must yield a FRESH snapshot per sample (on device: refresh between ticks).
public func poleFromAmbient(_ source: SignalSource, ticks: Int, drandRound: Data,
                            sensorDigest: Data = Data("ambient".utf8)) throws -> PoLEState {
    let gate = LivenessGate()
    for _ in 0..<ticks {
        let (psl, psnl) = ambientLivenessLikelihoods(try source.sample())
        gate.update(pSGivenLive: psl, pSGivenNotLive: psnl)
    }
    return gate.state(sensorDigest: sensorDigest, drandRound: drandRound)
}

/// Result of a source-driven ratchet step. `gatedOut == true` means the live gate
/// was closed (no signal present) and no advance happened (fail-closed).
public struct TimedTick {
    public let tick: ContinuityTick?
    public let intervalS: Double
    public let gatedOut: Bool
    public let sourceKind: String
    public let simulated: Bool
}

/// Drive ONE ratchet step from ANY SignalSource. Source-agnostic: swapping the
/// ambient source for the ring source needs NO change here. Mirrors the Python
/// `timed_ratchet_step`.
public func timedRatchetStep(device: Device, source: SignalSource, pole: PoLEState,
                             drandRound: Data, beacon: Data, challenge: Data = Data()) throws -> TimedTick {
    let s = try source.sample()
    if !s.present {
        return TimedTick(tick: nil, intervalS: 0.0, gatedOut: true,
                         sourceKind: s.kind, simulated: s.simulated)
    }
    let intervalS = try device.nextRatchetInterval(bioSignal: s.timing)   // WHEN, not value
    let tick = try device.continuityTick(pole, drandRound: drandRound, beacon: beacon, challenge: challenge)
    return TimedTick(tick: tick, intervalS: intervalS, gatedOut: false,
                     sourceKind: s.kind, simulated: s.simulated)
}
