import Foundation

/// Configurable t-of-n threshold protection for the TSK (§7.3, Inv 22). Mirrors
/// `backend/atlas/keys/tsk_threshold.py` (Python = reference-of-record).
///
/// Generalizes the fixed 2-of-2 (user_half ∧ server_half) into a user-chosen
/// threshold over an arbitrary holder set; default 2-of-3 (Wallet-SE / USB /
/// Server-HSM). Reuses `Shamir` (GF(256)) + the `ThresholdSeal` policy/holder
/// types. Enforces the anti-remote-recovery invariant (guardianship #4): no
/// all-institutional subset reaches threshold — every quorum needs a
/// present/personal holder, so servers/operators alone can never reconstruct.
public enum TSKThreshold {

    public enum TSKError: Error, Equatable {
        case allInstitutionalQuorum
        case holderCountMismatch(expected: Int, got: Int)
        case seedTooShort
    }

    public struct TSKShare: Equatable {
        public let holder: ThresholdSeal.Custodian
        public let share: Shamir.Share
        public init(holder: ThresholdSeal.Custodian, share: Shamir.Share) {
            self.holder = holder; self.share = share
        }
    }

    /// Default 2-of-3: two present/personal holders + one institutional (server HSM).
    /// institutional_count (1) < m (2) -> every 2-subset includes a present holder.
    /// Computed (not `static let`) so it's concurrency-safe under Swift 6 without
    /// requiring `Sendable` on the reused recovery-layer value types.
    public static var defaultPolicy: ThresholdSeal.ThresholdPolicy {
        try! ThresholdSeal.ThresholdPolicy(n: 3, m: 2)
    }
    public static var defaultHolders: [ThresholdSeal.Custodian] {
        [
            ThresholdSeal.Custodian(label: "wallet-se", institutional: false),
            ThresholdSeal.Custodian(label: "usb", institutional: false),
            ThresholdSeal.Custodian(label: "server-hsm", institutional: true),
        ]
    }

    private static func enforceInvariant(
        _ policy: ThresholdSeal.ThresholdPolicy, _ holders: [ThresholdSeal.Custodian]
    ) throws {
        guard holders.count == policy.n else {
            throw TSKError.holderCountMismatch(expected: policy.n, got: holders.count)
        }
        let institutional = holders.filter { $0.institutional }.count
        if institutional >= policy.m { throw TSKError.allInstitutionalQuorum }
    }

    /// Split `tskSeed` into `policy.n` shares (any `policy.m` reconstruct), one per holder.
    public static func splitTSK(
        _ tskSeed: Data,
        policy: ThresholdSeal.ThresholdPolicy = TSKThreshold.defaultPolicy,
        holders: [ThresholdSeal.Custodian] = TSKThreshold.defaultHolders
    ) throws -> [TSKShare] {
        guard tskSeed.count >= 32 else { throw TSKError.seedTooShort }
        try enforceInvariant(policy, holders)
        let shares = Shamir.split(tskSeed, n: policy.n, k: policy.m)
        return zip(holders, shares).map { TSKShare(holder: $0, share: $1) }
    }

    /// Reconstruct the TSK seed from >= m shares; refuses an all-institutional quorum.
    public static func reconstructTSK(_ shares: [TSKShare]) throws -> Data {
        if shares.count >= 2 && shares.allSatisfy({ $0.holder.institutional }) {
            throw TSKError.allInstitutionalQuorum
        }
        return Shamir.combine(shares.map { $0.share })
    }
}
