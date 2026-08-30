import Foundation

/// Recovery tiers (TRUST_LAYER.md #6) — the ladder from strongest/cheapest to last-resort.
/// Mirrors `backend/atlas/recovery/tiers.py`.
///
/// DEVICE_PRESENT (you hold a device/user-half) → SOCIAL (guardianship + ceremony half) →
/// PHYSICAL_SELF (name+password + a live recovery person). PHYSICAL_SELF is the FLOOR: you are
/// never permanently locked out — the last credential is you. Pure selection logic, no new
/// crypto, so no parity vectors; these are native-logic tests kept in lockstep with Python.
public enum RecoveryTiers {

    public enum RecoveryTierError: Error, Equatable { case noTierReachable }

    /// Ordered by assurance/convenience — higher is stronger & cheaper.
    public enum RecoveryTier: Int, CaseIterable, Comparable {
        case physicalSelf = 1   // the floor — always reachable by being you
        case social = 2
        case devicePresent = 3  // highest
        public static func < (a: RecoveryTier, b: RecoveryTier) -> Bool { a.rawValue < b.rawValue }
    }

    /// Which module executes each tier (documented delegation). Computed so it stays clear of
    /// Swift's shared-mutable-global concurrency check.
    public static var tierOwner: [RecoveryTier: String] {
        [.devicePresent: "recovery.threshold_seal",
         .social: "recovery.guardianship",
         .physicalSelf: "realid.recovery_anchor"]
    }

    /// What the user can currently supply. Each tier consumes a subset.
    public struct AvailableFactors {
        public let userHalf: Bool         // a device / user-TSK half in hand (DEVICE_PRESENT)
        public let guardianQuorum: Bool   // can reach the guardianship threshold (SOCIAL)
        public let namePassword: Bool     // remembers name+password — the ceremony half
        public let recoveryPerson: Bool   // can reach a live, accountable recovery person
        public let recoveryCard: Bool     // holds the SE recovery card (only used when policy requires it)
        public init(userHalf: Bool = false, guardianQuorum: Bool = false,
                    namePassword: Bool = false, recoveryPerson: Bool = false,
                    recoveryCard: Bool = false) {
            self.userHalf = userHalf; self.guardianQuorum = guardianQuorum
            self.namePassword = namePassword; self.recoveryPerson = recoveryPerson
            self.recoveryCard = recoveryCard
        }
    }

    /// The user's recovery-authenticity choice. Default preserves the TRUST_LAYER.md #6 ladder.
    /// `requireCardForSocial`: when true, the SOCIAL tier also requires the SE recovery card, so a
    /// guardian quorum + name/password alone will not recover and losing the card drops to the
    /// in-person floor. The user bears the loss from loose security, so the user owns the trade-off.
    public struct RecoveryPolicy {
        public let requireCardForSocial: Bool
        public init(requireCardForSocial: Bool = false) { self.requireCardForSocial = requireCardForSocial }
    }
    public static var defaultPolicy: RecoveryPolicy { RecoveryPolicy() }

    static func requirement(_ tier: RecoveryTier, _ f: AvailableFactors, _ policy: RecoveryPolicy) -> Bool {
        switch tier {
        case .devicePresent: return f.userHalf
        case .social:
            let base = f.guardianQuorum && f.namePassword     // quorum alone is not enough
            return policy.requireCardForSocial ? (base && f.recoveryCard) : base
        case .physicalSelf:  return f.namePassword && f.recoveryPerson  // the floor: you (any policy)
        }
    }

    /// Every tier the supplied factors can satisfy under the user's policy, strongest first.
    public static func reachableTiers(_ f: AvailableFactors,
                                      _ policy: RecoveryPolicy = RecoveryPolicy()) -> [RecoveryTier] {
        RecoveryTier.allCases.filter { requirement($0, f, policy) }.sorted(by: >)
    }

    /// The STRONGEST reachable tier under the user's policy. Throws `.noTierReachable` only if even
    /// the physical-self floor is unreachable (no name+password, or no recovery person).
    public static func selectTier(_ f: AvailableFactors,
                                  _ policy: RecoveryPolicy = RecoveryPolicy()) throws -> RecoveryTier {
        guard let top = reachableTiers(f, policy).first else { throw RecoveryTierError.noTierReachable }
        return top
    }

    /// True iff the physical-self floor is reachable — the guarantee the product makes, under any policy.
    public static func neverLockedOut(_ f: AvailableFactors) -> Bool {
        requirement(.physicalSelf, f, RecoveryPolicy())
    }
}
