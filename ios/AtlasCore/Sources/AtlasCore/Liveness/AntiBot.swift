import Foundation

/// Phone-only ANTI-BOT proof (Tier 1) + standalone OFFLINE verifier. Mirrors
/// `backend/atlas/liveness/antibot.py`. A live client answers a FRESH challenge by binding it to a
/// MOTION SUMMARY (a device digest of the IMU gesture + tap<->IMU coherence + pooled entropy) and
/// signs it; the verifier — no network, no server — rejects replay (one-shot), wrong-challenge,
/// no-physical-signal, and forged responses. Defeats the remote-software-bot / replay class.
///
/// The on-device signal processing that produces `motionSummary` from real CoreMotion IMU + touch
/// is the DEVICE SEAM (device-only). Proving "not a physical RIG" is Tier 2 (motion<->physiology).
public enum AntiBot {
    public static let gesture = "gesture"
    public static let tap = "tap"

    public struct Challenge {
        public var nonce: Data
        public var epoch: Int
        public var kind: String
        public init(nonce: Data, epoch: Int, kind: String = AntiBot.gesture) {
            self.nonce = nonce; self.epoch = epoch; self.kind = kind
        }
    }

    public static func issueChallenge(epoch: Int, kind: String = gesture) -> Challenge {
        Challenge(nonce: Primitives.randomBytes(16), epoch: epoch, kind: kind)
    }

    public struct Response {
        public var nonce: Data
        public var kind: String
        public var motionSummary: Data
        public var publicKey: HybridSign.PublicKey
        public var sig: Data
        public init(nonce: Data, kind: String, motionSummary: Data,
                    publicKey: HybridSign.PublicKey, sig: Data = Data()) {
            self.nonce = nonce; self.kind = kind; self.motionSummary = motionSummary
            self.publicKey = publicKey; self.sig = sig
        }
        public func body() -> Data {
            Primitives.H(Data("atlas/antibot/response".utf8), nonce, Data(kind.utf8), motionSummary)
        }
    }

    public static func respond(_ ch: Challenge, motionSummary: Data,
                               keypair: HybridSign.Keypair, publicKey: HybridSign.PublicKey) throws -> Response {
        var r = Response(nonce: ch.nonce, kind: ch.kind, motionSummary: motionSummary, publicKey: publicKey)
        r.sig = try HybridSign.sign(keypair, r.body())
        return r
    }

    public final class Verifier {
        private var seen: Set<Data> = []
        public init() {}
        public func verify(_ r: Response, _ ch: Challenge) -> Bool {
            guard r.nonce == ch.nonce, r.kind == ch.kind else { return false }   // bound to THIS fresh challenge
            guard !seen.contains(r.nonce) else { return false }                  // replay: one-shot
            guard !r.motionSummary.isEmpty else { return false }                 // no physical signal
            guard HybridSign.verify(r.publicKey, r.body(), r.sig) else { return false }
            seen.insert(r.nonce)
            return true
        }
    }

    // MARK: - Shake-to-prove-human (RNG-derived plan + escalating time-lock)
    //
    // Mirrors `backend/atlas/liveness/antibot.py`. The shake target is DERIVED
    // FROM THE FRESH CHALLENGE NONCE (issue_challenge's CSPRNG draw), so it can
    // neither be precomputed nor replayed. A plan is an ordered sequence of
    // (direction, count) segments; the user shakes UNTIL each segment's target
    // is reached, per direction. Repeated failures arm an escalating lockout.

    public static let upDown = "updown"
    public static let sideways = "sideways"
    private static let directions = [upDown, sideways]

    public struct ShakeSegment: Equatable {
        public let direction: String   // upDown | sideways
        public let count: Int
        public init(direction: String, count: Int) { self.direction = direction; self.count = count }
    }

    /// Byte-parity with Python `derive_shake_plan`: segment i takes
    /// seed = H("atlas/antibot/shake", nonce, i); byte 0 picks the direction,
    /// byte 1 picks the count in [minCount, maxCount].
    public static func deriveShakePlan(nonce: Data, segments: Int = 2,
                                       minCount: Int = 3, maxCount: Int = 6) -> [ShakeSegment] {
        precondition(segments >= 1, "segments must be >= 1")
        precondition(minCount >= 0 && minCount <= maxCount && maxCount <= 255,
                     "require 0 <= minCount <= maxCount <= 255")
        let span = maxCount - minCount + 1
        var plan: [ShakeSegment] = []
        for i in 0..<segments {
            let seed = Array(Primitives.H(Data("atlas/antibot/shake".utf8), nonce, Data([UInt8(i)])))
            let direction = directions[Int(seed[0]) % directions.count]
            let count = minCount + (Int(seed[1]) % span)
            plan.append(ShakeSegment(direction: direction, count: count))
        }
        return plan
    }

    /// Canonical digest pinning a whole plan (parity KAT / challenge binding).
    public static func shakePlanDigest(_ plan: [ShakeSegment]) -> Data {
        var buf = Data("atlas/antibot/shake/plan".utf8)
        for seg in plan {
            buf.append(Data(seg.direction.utf8))
            buf.append(UInt8(seg.count))
        }
        return Primitives.H(buf)
    }

    // MARK: Tap-to-prove-human (nonce-derived tap RHYTHM, IMU-detected)
    //
    // Alternative to the shake: tap the phone BODY in a challenge rhythm ("tap 3 · pause · tap 2").
    // A finger tap is a sharp accelerometer spike — crisp to detect, and there is NO ambiguous way
    // to perform it (a tap is a tap; fewer false failures, better accessibility). Derived from the
    // fresh nonce like the shake plan. (The hardware side button is NOT usable — iOS exposes no app
    // API for it; the IMU tap is the physical-button-equivalent the platform permits.)

    public struct TapSegment: Equatable, Sendable {
        public let count: Int
        public init(count: Int) { self.count = count }
    }

    /// Byte-parity with Python `derive_tap_plan`: segment i takes
    /// seed = H("atlas/antibot/tap", nonce, i); byte 0 picks the burst count in [minTaps, maxTaps].
    public static func deriveTapPlan(nonce: Data, segments: Int = 2,
                                     minTaps: Int = 2, maxTaps: Int = 5) -> [TapSegment] {
        precondition(segments >= 1, "segments must be >= 1")
        precondition(minTaps >= 0 && minTaps <= maxTaps && maxTaps <= 255,
                     "require 0 <= minTaps <= maxTaps <= 255")
        let span = maxTaps - minTaps + 1
        var plan: [TapSegment] = []
        for i in 0..<segments {
            let seed = Array(Primitives.H(Data("atlas/antibot/tap".utf8), nonce, Data([UInt8(i)])))
            plan.append(TapSegment(count: minTaps + (Int(seed[0]) % span)))
        }
        return plan
    }

    /// Canonical digest pinning a whole tap plan (parity KAT / challenge binding).
    public static func tapPlanDigest(_ plan: [TapSegment]) -> Data {
        var buf = Data("atlas/antibot/tap/plan".utf8)
        for seg in plan { buf.append(UInt8(seg.count)) }
        return Primitives.H(buf)
    }

    /// Escalating time-lock: the first `lockFreeTries` cumulative failures are
    /// free; each further failure doubles a 30s base lockout, capped at one hour.
    public static let lockFreeTries = 10
    private static let lockBaseS = 30
    private static let lockCapS = 3600

    public static func lockBackoffSeconds(failCount: Int) -> Int {
        if failCount <= lockFreeTries { return 0 }
        let over = failCount - lockFreeTries - 1
        if over >= 7 { return lockCapS }      // 30*2^7 = 3840 > 3600 cap; avoids shift/mul overflow
        return min(lockBaseS * (1 << over), lockCapS)
    }
}
