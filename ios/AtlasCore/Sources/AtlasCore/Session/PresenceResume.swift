import Foundation

/// Live-presence session lifecycle with resumption codes. Mirrors
/// `backend/atlas/session/presence_resume.py` (reference-of-record).
///
/// Presence is the ring's live pulse. A live session is NOT binary — a Bluetooth blip
/// must not nuke it, but a removal, a timeout, or a ring-SWAP across a gap must:
///
///  * `.present`   — live pulse; the presence gate is open.
///  * `.suspended` — the ring dropped; within a bounded grace window the session HOLDS
///    (gate closed, live keys not yet wiped). On reconnect the ring must present the next
///    RESUMPTION CODE to prove it is the SAME ring — not a swapped-in ring that also has a
///    pulse.
///  * `.locked`    — grace window expired, a wrong/absent code, or removal: hard lockdown
///    (the caller wipes the live layer, keeps the sealed identity) + an optional forensic
///    `LockEvent`. Terminal — re-presence is a NEW session.
///
/// Resumption codes are a one-time HKDF chain off the enrolment handshake-bind secret; the
/// ring and phone derive `resumeCode(bind, i)` independently, a swapped ring can't, and the
/// counter strictly advances so an old code is rejected. Times are passed in (deterministic).
/// GATES/TIMES the session — the codes authenticate continuity, never a key/value.

public func resumeCode(_ bindSecret: Data, _ counter: Int, length: Int = 16) -> Data {
    Primitives.hkdf(ikm: bindSecret,
                    info: Data("atlas/resume|".utf8) + Data(String(counter).utf8),
                    length: length)
}

public enum PresenceState: Sendable { case present, suspended, locked }

public struct LockEvent: Sendable, Equatable {
    public let reason: String    // "removed" | "timeout" | "bad_code"
    public let atS: Double
}

public final class PresenceSession {
    private let bind: Data
    private let graceS: Double
    public private(set) var state: PresenceState = .present
    private var counter = 0                 // next expected resumption-code index
    private var suspendedAt: Double?
    public private(set) var lockEvent: LockEvent?

    public init(bindSecret: Data, atS: Double, graceS: Double = 30) {
        precondition(!bindSecret.isEmpty, "bindSecret required (from the enrolment handshake)")
        self.bind = bindSecret
        self.graceS = graceS
    }

    /// Is the presence gate open right now? (Only in `.present`.)
    public var operating: Bool { state == .present }

    /// A fresh live pulse was observed on the ring. No effect once `.locked` (terminal).
    public func pulse(atS: Double) {
        if state == .locked { return }
        state = .present
        suspendedAt = nil
    }

    /// The ring dropped / pulse lost — enter the grace window (do NOT wipe yet).
    public func disconnect(atS: Double) {
        if state == .present { state = .suspended; suspendedAt = atS }
    }

    /// Call while `.suspended`: lock if the grace window has elapsed. True iff it locked.
    @discardableResult
    public func checkTimeout(atS: Double) -> Bool {
        if state == .suspended, let s = suspendedAt, atS - s > graceS {
            lock("timeout", atS); return true
        }
        return false
    }

    /// The ring reconnected and presents a resumption code. Returns true (RESUMED) iff
    /// `.suspended`, within the grace window, and the code matches the next expected one.
    /// Otherwise LOCKS (fail-closed).
    @discardableResult
    public func reconnect(code: Data, atS: Double) -> Bool {
        guard state == .suspended, let s = suspendedAt else { return false }
        if atS - s > graceS { lock("timeout", atS); return false }
        let expected = resumeCode(bind, counter)
        guard Self.constantTimeEqual(code, expected) else { lock("bad_code", atS); return false }
        counter += 1                          // one-time: advance so this code can't replay
        state = .present
        suspendedAt = nil
        return true
    }

    /// Explicit removal (or a decision to hard-lock now). Terminal.
    public func remove(atS: Double) { lock("removed", atS) }

    private func lock(_ reason: String, _ atS: Double) {
        state = .locked
        suspendedAt = nil
        lockEvent = LockEvent(reason: reason, atS: atS)
    }

    private static func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for (x, y) in zip(a, b) { diff |= x ^ y }
        return diff == 0
    }
}
