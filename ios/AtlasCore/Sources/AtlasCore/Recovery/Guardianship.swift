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

        public init(guardians: [Guardian], m: Int, minWittingApprovals: Int = 0) throws {
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
            self.guardians = guardians; self.m = m; self.minWittingApprovals = minWittingApprovals
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
                                   wittingVetoes: [String] = []) throws -> Data {
        let witting = policy.wittingLabels
        let realVetoes = Set(wittingVetoes).intersection(witting)
        guard realVetoes.isEmpty else { throw GuardianshipError.wittingVeto(count: realVetoes.count) }
        let realApprovals = Set(wittingApprovals).intersection(witting)
        guard realApprovals.count >= policy.minWittingApprovals else {
            throw GuardianshipError.approvalsNotMet(need: policy.minWittingApprovals,
                                                    got: realApprovals.count)
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
