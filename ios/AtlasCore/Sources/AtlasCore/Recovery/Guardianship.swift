import Foundation

/// Guardianship — the recovery net (TRUST_LAYER.md #4/#5). Mirrors
/// `backend/atlas/recovery/guardianship.py`.
///
/// A PRIVATE guardian set (only the user knows the full membership) of SILENT device-node
/// custodians (passive, opaque, anti-collusion/anti-coercion) and WITTING human guardians (can
/// veto / must approve). Structural invariant (#4): institutional guardians < m, so no
/// all-institutional subset reaches threshold — servers/operators alone can never recover you.
///
/// This adds POLICY, not new crypto: it composes `ThresholdSeal`. There is no new keyed
/// derivation, so there are no new parity vectors — the byte-level seal is already parity-covered
/// by ThresholdSeal. These are native-logic tests kept in lockstep with the Python reference.
public enum Guardianship {

    public enum GuardianshipError: Error, Equatable {
        case policyInvalid(String)
        case institutionalThreshold(String)   // an all-institutional subset could/does reach threshold
        case wittingVeto(count: Int)          // a human said no
        case approvalsNotMet(need: Int, got: Int)
        case cardRequired                     // policy requires the SE recovery card; no valid card sig
    }

    /// The message the SE recovery card signs to authorize a guardian recovery, bound to the sealed
    /// sketch's context so a card authorization cannot be replayed across recoveries.
    public static func cardRecoveryMessage(context: Data) -> Data {
        Primitives.H(Data("atlas/guardianship/card/v1".utf8), context)
    }

    public enum GuardianKind: String {
        case silent    // passive device node; holds a share, no interaction, may be unaware
        case witting   // a human who knows they are a guardian; can veto / must approve
    }

    public struct Guardian: Equatable {
        public let custodian: ThresholdSeal.Custodian
        public let kind: GuardianKind
        public init(custodian: ThresholdSeal.Custodian, kind: GuardianKind) {
            self.custodian = custodian; self.kind = kind
        }
        public var label: String { custodian.label }
        public var institutional: Bool { custodian.institutional }
    }

    public struct GuardianShare: Equatable {
        public let guardian: Guardian
        public let share: Shamir.Share
        public init(guardian: Guardian, share: Shamir.Share) {
            self.guardian = guardian; self.share = share
        }
    }

    /// Configurable m-of-n over a private guardian set (#5), with the anti-collusion invariant
    /// (#4) enforced at construction.
    public struct GuardianshipPolicy {
        public let guardians: [Guardian]
        public let m: Int
        public let minWittingApprovals: Int
        // The user's authenticity choice (mirrors RecoveryTiers.RecoveryPolicy.requireCardForSocial):
        // when true, guardian recovery ALSO requires a valid signature from the SE recovery card, so a
        // guardian quorum alone cannot reopen the sketch and losing the card forces in-person recovery.
        public let requireCard: Bool
        public let cardPub: HybridSign.PublicKey?

        public init(guardians: [Guardian], m: Int, minWittingApprovals: Int = 0,
                    requireCard: Bool = false, cardPub: HybridSign.PublicKey? = nil) throws {
            // validates 1 < m <= n < 256 (throws ThresholdSeal.SealError.policyInvalid)
            _ = try ThresholdSeal.ThresholdPolicy(n: guardians.count, m: m)
            let institutional = guardians.filter { $0.institutional }.count
            guard institutional < m else {
                throw GuardianshipError.institutionalThreshold(
                    "\(institutional) institutional guardians >= threshold \(m): an "
                    + "all-institutional subset could recover you (need institutional_count < m)")
            }
            let witting = guardians.filter { $0.kind == .witting }.count
            guard (0...witting).contains(minWittingApprovals) else {
                throw GuardianshipError.policyInvalid(
                    "minWittingApprovals=\(minWittingApprovals) outside [0, \(witting)]")
            }
            guard !(requireCard && cardPub == nil) else {
                throw GuardianshipError.policyInvalid("requireCard is set but no cardPub was provided")
            }
            self.guardians = guardians; self.m = m; self.minWittingApprovals = minWittingApprovals
            self.requireCard = requireCard; self.cardPub = cardPub
        }

        public var n: Int { guardians.count }
        func thresholdPolicy() throws -> ThresholdSeal.ThresholdPolicy {
            try ThresholdSeal.ThresholdPolicy(n: n, m: m)
        }
        var wittingLabels: Set<String> {
            Set(guardians.filter { $0.kind == .witting }.map { $0.label })
        }
    }

    /// Seal `secret` under (userHalf ∧ m-of-n guardians).
    public static func seal(_ secret: Data, userHalf: Data, policy: GuardianshipPolicy,
                            storage: ThresholdSeal.StorageLocation,
                            context: Data = Data()) throws -> (ThresholdSeal.SealedSketch, [GuardianShare]) {
        let (sealed, cshares) = try ThresholdSeal.seal(
            secret, userHalf: userHalf, custodians: policy.guardians.map { $0.custodian },
            policy: try policy.thresholdPolicy(), storage: storage, context: context)
        let gshares = zip(policy.guardians, cshares).map {
            GuardianShare(guardian: $0, share: $1.share)
        }
        return (sealed, gshares)
    }

    /// Reopen a guardianship-sealed secret. Checks (all fail-closed, in order): witting veto →
    /// witting approvals → anti-collusion (reject an all-institutional presented set) → threshold.
    public static func reconstruct(_ sealed: ThresholdSeal.SealedSketch, userHalf: Data,
                                   presentedShares: [GuardianShare], policy: GuardianshipPolicy,
                                   wittingApprovals: [String] = [],
                                   wittingVetoes: [String] = [],
                                   cardSignature: Data? = nil) throws -> Data {
        let witting = policy.wittingLabels
        let realVetoes = Set(wittingVetoes).intersection(witting)
        guard realVetoes.isEmpty else { throw GuardianshipError.wittingVeto(count: realVetoes.count) }
        let realApprovals = Set(wittingApprovals).intersection(witting)
        guard realApprovals.count >= policy.minWittingApprovals else {
            throw GuardianshipError.approvalsNotMet(need: policy.minWittingApprovals,
                                                    got: realApprovals.count)
        }
        if policy.requireCard {
            // BINDING (parity with guardianship.py): without a valid card signature over the sketch's
            // context, guardian recovery fails closed — dropping the user to the in-person floor.
            guard let cardPub = policy.cardPub, let sig = cardSignature,
                  HybridSign.verify(cardPub, cardRecoveryMessage(context: sealed.context), sig)
            else { throw GuardianshipError.cardRequired }
        }
        if !presentedShares.isEmpty && presentedShares.allSatisfy({ $0.guardian.institutional }) {
            throw GuardianshipError.institutionalThreshold(
                "presented shares are all institutional — a non-institutional party is required")
        }
        let cshares = presentedShares.map {
            ThresholdSeal.CustodianShare(custodian: $0.guardian.custodian, share: $0.share)
        }
        return try ThresholdSeal.unseal(sealed, userHalf: userHalf, custodianShares: cshares)
    }
}
