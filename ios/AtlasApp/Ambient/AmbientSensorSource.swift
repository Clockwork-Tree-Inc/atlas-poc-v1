import Foundation
import CoreMotion
import AVFoundation
import AtlasCore
#if canImport(UIKit)
import UIKit
#endif

/// The iPhone's fused multimodal ambient stream as the live TIMING/GATING source
/// — the STAND-IN for the R10 ring in this build (ambient-not-biological).
///
/// FRESH-PER-TICK, ON-DEMAND (Locked Model B4): this is NOT a continuous
/// background stream the ratchet dips into. Each ratchet tick PULLS a fresh
/// snapshot: `refreshSnapshot()` briefly activates the sensors, captures one fused
/// window, and deactivates. Order per tick: tick fires → `refreshSnapshot()` →
/// the fresh window times/gates that tick → tick completes. This matches the
/// no-cache fresh-consumption invariant (a fresh per-tick sample is hard to
/// replay) and saves battery (continuous cost belongs on the ring, where liveness
/// requires it).
///
/// LOAD-BEARING INVARIANT: the fused window drives WHEN the QRNG fires and whether
/// the ratchet advances (the gate) — it is NEVER folded into a key/value. The
/// value stays clean QRNG (`PoLE.firePoLEValue`). Do not add any path routing
/// `fusedWindow()` into a KDF.
///
/// Exposes a `SignalSource` via `AtlasCore.ClosureSignalSource` (returns the most
/// recent snapshot), so the pipeline stays source-agnostic: the ring drops in with
/// the same interface, no pipeline change.
///
/// STATUS: written against real CoreMotion/AVFoundation; unrun until built on a Mac
/// to a device (needs mic + motion usage strings in Info.plist). The exact
/// one-shot activation windows below want on-device tuning.
// `@unchecked Sendable`: `refreshSnapshot()` reads motion, barometer and mic
// CONCURRENTLY (`async let`) for a tight per-tick window, which sends `self` into
// child tasks. That is safe here — the three reads touch independent hardware,
// all sensor callbacks are funnelled through the serial `sensorQueue`, and the
// only shared state (`latestWindow`) is guarded by `lock`. The compiler can't
// prove this, so we assert it.
public final class AmbientSensorSource: @unchecked Sendable {

    public static let channels = [
        "microphone", "accelerometer", "gyroscope", "magnetometer",
        "barometer", "ambient_light",
    ]

    private let motion = CMMotionManager()
    private let altimeter = CMAltimeter()

    // A dedicated serial queue for ALL sensor callbacks + read timeouts, so the
    // per-tick sensor burst never runs on the main thread (keeps the UI smooth).
    // Being serial, it also serializes each read's one-shot `done` flag race-free.
    private let sensorQueue = DispatchQueue(label: "inc.clockworktree.atlas.ambient.sensors")
    private lazy var sensorOpQueue: OperationQueue = {
        let q = OperationQueue()
        q.underlyingQueue = sensorQueue
        q.maxConcurrentOperationCount = 1
        return q
    }()

    // The latest fused snapshot (TIMING/PRESENCE features only — never key material).
    private var latestWindow = Data()
    private var lastAltitude: Double?
    private let lock = NSLock()

    public init() {}

    // MARK: - the SignalSource seam

    /// A source-agnostic `SignalSource` backed by the most recent per-tick
    /// snapshot. The runtime calls `refreshSnapshot()` immediately before each
    /// `timedRatchetStep`, so `sample()` sees fresh bytes.
    public func asSignalSource() -> SignalSource {
        // Change-detecting (not level): each fused window is XOR'd against the
        // previous and entropy is measured across snapshots. Mirrors the Python
        // AmbientSensorSource. Presence/timing come from CHANGE, so a loud-but-steady
        // room contributes nothing and a frozen/looped feed fails closed.
        ChangeDetectingSignalSource(kind: "ambient", simulated: true,
                                    channels: AmbientSensorSource.channels, liveFloor: 2) { [weak self] in
            self?.fusedWindow() ?? Data()
        }
    }

    public func fusedWindow() -> Data {
        lock.lock(); defer { lock.unlock() }
        return latestWindow
    }

    /// Synchronous, non-suspending store of the latest window. Kept out of the
    /// `async` body so the lock is never held across a suspension point (Swift 6
    /// flags `NSLock.lock()` used directly in an async context).
    private func storeWindow(_ window: Data) {
        lock.lock(); latestWindow = window; lock.unlock()
    }

    // MARK: - fresh-per-tick on-demand pull

    /// Pull ONE fresh fused window: briefly activate the sensors, read a snapshot,
    /// deactivate. Call once per ratchet tick (NOT continuously). Timing/presence
    /// features only — nothing here becomes key material.
    public func refreshSnapshot() async {
        async let motionFeat = readMotionOnce()
        async let baro = readBarometerOnce()
        let (m, b) = await (motionFeat, baro)
        // ADAPTIVE mic: sample it ONLY when nothing else is playing. If music or a
        // call is active (`isOtherAudioPlaying`), skip the mic entirely so we never
        // compete for it or drop Bluetooth audio to call quality — presence runs on
        // the motion channels alone. Quiet -> mic contributes; audio playing -> 0.
        let otherAudioPlaying = AVAudioSession.sharedInstance().isOtherAudioPlaying
        let micLevel: Double = (AtlasFlags.useAmbientMic && !otherAudioPlaying) ? await readMicBurst() : 0

        func byte(_ x: Double, _ scale: Double) -> UInt8 {
            UInt8(min(max(x * scale, 0), 255))
        }
        // A clean per-channel SNAPSHOT of "the room right now" — each byte quantizes
        // one real channel's reading (accel, gyro, mag, baro, mic), plus finer-scale
        // copies of the most dynamic channels so a SMALL live change still flips
        // bits. The change-detector (ChangeDetectingSignalSource) XORs successive
        // snapshots: presence + timing come from what CHANGED, not the absolute
        // level, so there is no hand-mixed "timing byte" here anymore. Nothing here
        // is ever folded into a key/value — snapshot bytes only time/gate.
        let bytes: [UInt8] = [
            byte(m.accel, 255), byte(m.gyro, 64), byte(m.mag, 4), byte(b, 512),
            byte(micLevel, 255),
            byte(m.accel, 2048), byte(m.gyro, 512), byte(micLevel, 4096),
        ]
        storeWindow(Data(bytes))
    }

    // MARK: - one-shot channel reads

    private struct MotionFeat { let accel, gyro, mag: Double }

    private func readMotionOnce() async -> MotionFeat {
        await withCheckedContinuation { cont in
            guard motion.isDeviceMotionAvailable else {
                return cont.resume(returning: MotionFeat(accel: 0, gyro: 0, mag: 0))
            }
            // `startDeviceMotionUpdates` STREAMS — the handler fires repeatedly. Guard
            // so the continuation resumes EXACTLY ONCE (first sample or the timeout),
            // else Swift traps "continuation resumed more than once". The handler and
            // the timeout both run on the main queue, so this Bool needs no lock.
            var done = false
            func finish(_ f: MotionFeat) {
                if done { return }
                done = true
                self.motion.stopDeviceMotionUpdates()
                cont.resume(returning: f)
            }
            motion.deviceMotionUpdateInterval = 0.05
            motion.startDeviceMotionUpdates(to: sensorOpQueue) { dm, _ in
                guard let dm else { return }
                let a = dm.userAcceleration, r = dm.rotationRate, f = dm.magneticField.field
                finish(MotionFeat(
                    accel: sqrt(a.x*a.x + a.y*a.y + a.z*a.z),
                    gyro: sqrt(r.x*r.x + r.y*r.y + r.z*r.z),
                    mag: sqrt(f.x*f.x + f.y*f.y + f.z*f.z)))
            }
            // safety timeout: if no sample lands quickly, resume with zeros (gate closes).
            sensorQueue.asyncAfter(deadline: .now() + 0.3) { finish(MotionFeat(accel: 0, gyro: 0, mag: 0)) }
        }
    }

    private func readBarometerOnce() async -> Double {
        await withCheckedContinuation { cont in
            guard CMAltimeter.isRelativeAltitudeAvailable() else { return cont.resume(returning: 0) }
            // Same one-shot guard: the altimeter also streams. Handler + timeout on main.
            var done = false
            func finish(_ v: Double) {
                if done { return }
                done = true
                self.altimeter.stopRelativeAltitudeUpdates()
                cont.resume(returning: v)
            }
            altimeter.startRelativeAltitudeUpdates(to: sensorOpQueue) { data, _ in
                guard let data else { return }
                let alt = data.relativeAltitude.doubleValue
                let delta = self.lastAltitude.map { abs(alt - $0) } ?? 0
                self.lastAltitude = alt
                finish(delta)
            }
            sensorQueue.asyncAfter(deadline: .now() + 0.3) { finish(0) }
        }
    }

    /// A SHORT on-demand audio burst (loudness only — not recorded, never stored).
    private func readMicBurst() async -> Double {
        await withCheckedContinuation { cont in
            let engine = AVAudioEngine()
            let session = AVAudioSession.sharedInstance()
            // `.mixWithOthers`: sample the mic for the ambient loudness feature
            // WITHOUT interrupting the user's music/podcast. (Previously `.record`
            // with no options deactivated other apps' audio — that's why playback
            // stopped.) The orange mic indicator still shows while active — honest:
            // the mic IS briefly on. We read one RMS loudness value into the fused
            // window and tear down; no audio is recorded or stored.
            try? session.setCategory(.record, mode: .measurement, options: [.mixWithOthers])
            try? session.setActive(true)
            let input = engine.inputNode
            // One-shot guard. The tap fires on a realtime audio thread; funnel every
            // completion through the main queue so `done` is touched on one thread only
            // and the continuation resumes exactly once (tap sample OR timeout).
            var done = false
            func finish(_ v: Double) {
                if done { return }
                done = true
                input.removeTap(onBus: 0)
                engine.stop()
                cont.resume(returning: v)
            }
            input.installTap(onBus: 0, bufferSize: 1024, format: input.inputFormat(forBus: 0)) { buffer, _ in
                guard let ch = buffer.floatChannelData?[0] else { return }
                let n = Int(buffer.frameLength)
                var sum: Float = 0
                for i in 0..<n { sum += ch[i] * ch[i] }
                let rms = n > 0 ? sqrt(sum / Float(n)) : 0
                self.sensorQueue.async { finish(Double(rms)) }
            }
            do { try engine.start() } catch { sensorQueue.async { finish(0) }; return }
            sensorQueue.asyncAfter(deadline: .now() + 0.25) { finish(0) }
        }
    }
}
