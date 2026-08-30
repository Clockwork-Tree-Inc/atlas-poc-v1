import Foundation

/// Unlock tiers + presence state machine — the MAX tier is held ONLY while live presence is fresh.
/// Swift parity with `backend/atlas/session/presence_unlock.py` (Python reference of record).
///
/// Two gates compose fail-closed: the UNLOCK TIER reached at authentication, and PRESENCE FRESHNESS
/// (MAX is earned tick-by-tick — each PoLE tick stamps the current beacon round; if none lands
/// within `freshnessWindowRounds`, presence goes stale and the effective tier drops to STANDARD).
/// A duress unlock caps the effective tier at a scoped DURESS level regardless of presence.
public enum PresenceUnlock {

    public enum UnlockTier: Int, Comparable {
        case locked = 0
        case duress = 1        // scoped, limited view reached via the duress code (never MAX)
        case basic = 2         // Face ID / biometric
        case standard = 3      // + passcode
        case max = 4           // + continuous live presence (PoLE)
        public static func < (a: UnlockTier, b: UnlockTier) -> Bool { a.rawValue < b.rawValue }
    }

    public struct Policy {
        public let freshnessWindowRounds: UInt64
        public init(freshnessWindowRounds: UInt64) {
            precondition(freshnessWindowRounds > 0, "freshnessWindowRounds must be > 0")
            self.freshnessWindowRounds = freshnessWindowRounds
        }
    }

    public struct State {
        public var unlockedTier: UnlockTier = .locked
        public var lastPresenceRound: UInt64? = nil
        public var duress: Bool = false
        public init() {}
    }

    public static func onUnlock(_ s: inout State, tier: UnlockTier, duress: Bool = false) {
        if duress { s.duress = true; s.unlockedTier = .duress }
        else { s.duress = false; s.unlockedTier = tier }
    }

    /// A fresh PoLE tick at `nowRound` — only advances the clock, never regresses it.
    public static func onPresenceTick(_ s: inout State, nowRound: UInt64) {
        if s.lastPresenceRound == nil || nowRound > s.lastPresenceRound! { s.lastPresenceRound = nowRound }
    }

    public static func onLock(_ s: inout State) {
        s.unlockedTier = .locked; s.lastPresenceRound = nil; s.duress = false
    }

    public static func presenceLive(_ s: State, _ p: Policy, nowRound: UInt64) -> Bool {
        guard let r = s.lastPresenceRound, nowRound >= r else { return false }
        return nowRound - r <= p.freshnessWindowRounds
    }

    /// The tier in force right now: the unlock ceiling, lowered if presence isn't live. MAX needs
    /// fresh presence (else STANDARD); duress caps at DURESS.
    public static func effectiveTier(_ s: State, _ p: Policy, nowRound: UInt64) -> UnlockTier {
        if s.duress { return .duress }
        if s.unlockedTier < .max { return s.unlockedTier }
        return presenceLive(s, p, nowRound: nowRound) ? .max : .standard
    }

    public static func allows(_ s: State, _ p: Policy, nowRound: UInt64, required: UnlockTier) -> Bool {
        effectiveTier(s, p, nowRound: nowRound) >= required
    }
}
