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

    /// A QRNG-drawn capture duration for THIS tick, bounded to [lo, hi]. Randomizing the
    /// window WIDTH (and, with the sensor-derived tick interval, the sampling INSTANT) makes
    /// the exact slice of time we sample unpredictable — strengthening anti-replay (a looped or
    /// synthetic feed can't anticipate the window) without starving the presence change-detector,
    /// which is why it stays bounded rather than fully wild.
    private static func randomWindow(_ lo: Double, _ hi: Double) -> Double {
        var b: UInt8 = 0
        _ = SecRandomCopyBytes(kSecRandomDefault, 1, &b)
        return lo + (Double(b) / 255.0) * (hi - lo)
    }

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
        #if targetEnvironment(simulator)
        // SIMULATOR ONLY (never compiled into a device build): the Simulator has no motion/
        // mic/baro sensors, so the real reads all return zeros, the change-detector sees no
        // change, and the presence gate would never open — blocking enrolment. Synthesize a
        // fresh-each-tick window so the FULL app (persona/vault/messaging/history) is
        // exercisable in the Simulator. This is a test affordance, loudly scoped; on device
        // the real sensor path below runs.
        storeWindow(Data((0..<8).map { _ in UInt8.random(in: 0...255) }))
        return
        #endif
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
            UInt8(min(max(abs(x) * scale, 0), 255))
        }
        // MAXIMUM-ENTROPY per-tick SNAPSHOT: every axis of every available channel is
        // quantized into the window (not collapsed to magnitudes) — so the harvest and
        // the duress evidence carry the richest live picture the hardware can give.
        //   motion: userAccel x/y/z · rotationRate x/y/z · gravity x/y/z ·
        //           attitude roll/pitch/yaw · magneticField x/y/z · heading
        //   environment: barometric altitude-delta · mic RMS
        //   device churn: uptime-nanosecond fraction · battery · thermal state
        // (device churn adds entropy that keeps flowing even when the phone is still.)
        var bytes: [UInt8] = [
            byte(m.ax, 2048), byte(m.ay, 2048), byte(m.az, 2048),
            byte(m.rx, 512), byte(m.ry, 512), byte(m.rz, 512),
            byte(m.gx, 128), byte(m.gy, 128), byte(m.gz, 128),
            byte(m.roll, 40), byte(m.pitch, 40), byte(m.yaw, 40),
            byte(m.mx, 4), byte(m.my, 4), byte(m.mz, 4), byte(m.heading, 0.7),
            byte(b, 512), byte(micLevel, 255), byte(micLevel, 4096),
        ]
        bytes.append(contentsOf: Self.deviceChurnBytes())
        // TIMING byte (index 0, consumed by Cadence.nextInterval): a mix of the WHOLE
        // window via a cheap avalanche fold, so the tick INTERVAL draws on ALL channels'
        // entropy — not one collapsed accel byte. Still only times/gates; never a key.
        var mix: UInt8 = 0xA5
        for (i, v) in bytes.enumerated() { mix = (mix &+ v) ^ (mix << 1 | mix >> 7) ^ UInt8(i & 0xff) }
        storeWindow(Data([mix] + bytes))
    }

    /// Cheap device-state churn — entropy that keeps changing even when the phone is
    /// perfectly still (uptime nanoseconds dominate). Times/gates only, never keyed.
    private static func deviceChurnBytes() -> [UInt8] {
        let upt = ProcessInfo.processInfo.systemUptime
        let nanoFrac = UInt64((upt - floor(upt)) * 1_000_000_000)
        var out: [UInt8] = [
            UInt8(nanoFrac & 0xff), UInt8((nanoFrac >> 8) & 0xff),
            UInt8((nanoFrac >> 16) & 0xff), UInt8((nanoFrac >> 24) & 0xff),
        ]
        #if canImport(UIKit)
        UIDevice.current.isBatteryMonitoringEnabled = true
        let lvl = UIDevice.current.batteryLevel                       // -1 if unknown
        out.append(UInt8(min(max((lvl < 0 ? 0.5 : Double(lvl)) * 255, 0), 255)))
        out.append(UInt8(ProcessInfo.processInfo.thermalState.rawValue & 0xff))
        #endif
        return out
    }

    // MARK: - one-shot channel reads

    // Full per-axis motion features (no magnitude collapse) — maximum entropy for the
    // window + duress evidence. `accel/gyro/mag` magnitudes are retained for the
    // change-detector's presence floor.
    private struct MotionFeat {
        let ax, ay, az, rx, ry, rz, gx, gy, gz: Double
        let roll, pitch, yaw, mx, my, mz, heading: Double
        var accel: Double { sqrt(ax*ax + ay*ay + az*az) }
        static let zero = MotionFeat(ax: 0, ay: 0, az: 0, rx: 0, ry: 0, rz: 0,
                                     gx: 0, gy: 0, gz: 0, roll: 0, pitch: 0, yaw: 0,
                                     mx: 0, my: 0, mz: 0, heading: 0)
    }

    private func readMotionOnce() async -> MotionFeat {
        await withCheckedContinuation { cont in
            guard motion.isDeviceMotionAvailable else {
                return cont.resume(returning: .zero)
            }
            // `startDeviceMotionUpdates` STREAMS — the handler fires repeatedly. Guard
            // so the continuation resumes EXACTLY ONCE (first sample or the timeout),
            // else Swift traps "continuation resumed more than once". The handler and
            // the timeout both run on the serial sensor queue, so this Bool needs no lock.
            var done = false
            func finish(_ f: MotionFeat) {
                if done { return }
                done = true
                self.motion.stopDeviceMotionUpdates()
                cont.resume(returning: f)
            }
            motion.deviceMotionUpdateInterval = 0.05
            motion.startDeviceMotionUpdates(using: .xTrueNorthZVertical, to: sensorOpQueue) { dm, _ in
                guard let dm else { return }
                let a = dm.userAcceleration, r = dm.rotationRate
                let g = dm.gravity, at = dm.attitude, f = dm.magneticField.field
                finish(MotionFeat(
                    ax: a.x, ay: a.y, az: a.z, rx: r.x, ry: r.y, rz: r.z,
                    gx: g.x, gy: g.y, gz: g.z,
                    roll: at.roll, pitch: at.pitch, yaw: at.yaw,
                    mx: f.x, my: f.y, mz: f.z, heading: dm.heading))
            }
            // RANDOM window width (bounded): the sample instant is already non-periodic
            // (sensor-derived tick interval); a QRNG-drawn timeout makes the width secret too.
            sensorQueue.asyncAfter(deadline: .now() + Self.randomWindow(0.15, 0.35)) { finish(.zero) }
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
            sensorQueue.asyncAfter(deadline: .now() + Self.randomWindow(0.18, 0.32)) { finish(0) }
        }
    }
}
