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
        public init(userHalf: Bool = false, guardianQuorum: Bool = false,
                    namePassword: Bool = false, recoveryPerson: Bool = false) {
            self.userHalf = userHalf; self.guardianQuorum = guardianQuorum
            self.namePassword = namePassword; self.recoveryPerson = recoveryPerson
        }
    }

    static func requirement(_ tier: RecoveryTier, _ f: AvailableFactors) -> Bool {
        switch tier {
        case .devicePresent: return f.userHalf
        case .social:        return f.guardianQuorum && f.namePassword  // quorum alone is not enough
        case .physicalSelf:  return f.namePassword && f.recoveryPerson  // the floor: you
        }
    }

    /// Every tier the supplied factors can satisfy, strongest first.
    public static func reachableTiers(_ f: AvailableFactors) -> [RecoveryTier] {
        RecoveryTier.allCases.filter { requirement($0, f) }.sorted(by: >)
    }

    /// The STRONGEST reachable tier. Throws `.noTierReachable` only if even the physical-self
    /// floor is unreachable (no name+password, or no recovery person).
    public static func selectTier(_ f: AvailableFactors) throws -> RecoveryTier {
        guard let top = reachableTiers(f).first else { throw RecoveryTierError.noTierReachable }
        return top
    }

    /// True iff the physical-self floor is reachable — the guarantee the product makes.
    public static func neverLockedOut(_ f: AvailableFactors) -> Bool {
        requirement(.physicalSelf, f)
    }
}
