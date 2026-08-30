import Foundation

/// Two-tier TSK recovery — `Shamir(your-half) ∧ Shamir(server-half)`, both mandatory.
/// Swift parity with `backend/atlas/keys/tsk_two_tier.py` (Python reference of record).
///
///   TSK seed = user_half XOR server_half
///   user_half   -> Shamir t-of-n over YOUR holders (phone SE, USB, your devices, contact)
///   server_half -> Shamir k-of-m over the server side (nodes/operators)
///
/// The server/institutional side only ever holds shares of `server_half`, which is an
/// independent value revealing nothing about the seed — so no subset of the server side,
/// even all of it, can reconstruct the TSK without a threshold of YOUR holders. The
/// anti-institutional property is structural, not a policy check.
public enum TSKTwoTier {

    public enum TwoTierError: Error, Equatable {
        case thresholdNotMet, holderClass, seedTooShort, holderCount
    }

    public struct TSKShare: Equatable {
        public let holder: ThresholdSeal.Custodian
        public let share: Shamir.Share
        public init(holder: ThresholdSeal.Custodian, share: Shamir.Share) {
            self.holder = holder; self.share = share
        }
    }

    public struct TwoTierShares {
        public let userShares: [TSKShare]
        public let serverShares: [TSKShare]
        public let userPolicy: ThresholdSeal.ThresholdPolicy
        public let serverPolicy: ThresholdSeal.ThresholdPolicy
    }

    static func xor(_ a: Data, _ b: Data) -> Data { Data(zip(a, b).map { $0 ^ $1 }) }

    public static func split(
        seed: Data,
        userHolders: [ThresholdSeal.Custodian],
        serverHolders: [ThresholdSeal.Custodian],
        userPolicy: ThresholdSeal.ThresholdPolicy,
        serverPolicy: ThresholdSeal.ThresholdPolicy,
        rng: (Int) -> Data = { Primitives.randomBytes($0) }
    ) throws -> TwoTierShares {
        guard seed.count >= 32 else { throw TwoTierError.seedTooShort }
        guard userHolders.count == userPolicy.n, serverHolders.count == serverPolicy.n
        else { throw TwoTierError.holderCount }
        guard !userHolders.contains(where: { $0.institutional }) else { throw TwoTierError.holderClass }
        guard serverHolders.allSatisfy({ $0.institutional }) else { throw TwoTierError.holderClass }

        let userHalf = rng(seed.count)
        let serverHalf = xor(seed, userHalf)
        let userRaw = Shamir.split(userHalf, n: userPolicy.n, k: userPolicy.m)
        let serverRaw = Shamir.split(serverHalf, n: serverPolicy.n, k: serverPolicy.m)
        return TwoTierShares(
            userShares: zip(userHolders, userRaw).map { TSKShare(holder: $0, share: $1) },
            serverShares: zip(serverHolders, serverRaw).map { TSKShare(holder: $0, share: $1) },
            userPolicy: userPolicy, serverPolicy: serverPolicy)
    }

    public static func reconstruct(
        userShares: [TSKShare],
        serverShares: [TSKShare],
        userPolicy: ThresholdSeal.ThresholdPolicy,
        serverPolicy: ThresholdSeal.ThresholdPolicy
    ) throws -> Data {
        guard userShares.count >= userPolicy.m else { throw TwoTierError.thresholdNotMet }
        guard serverShares.count >= serverPolicy.m else { throw TwoTierError.thresholdNotMet }
        let userHalf = Shamir.combine(userShares.map { $0.share })
        let serverHalf = Shamir.combine(serverShares.map { $0.share })
        return xor(userHalf, serverHalf)
    }

    /// Default holders matching the app's intent: your-half {phone SE, USB, contact} (2-of-3),
    /// server-half {node-a, node-b, node-c} (2-of-3).
    public static func defaultHolders() -> (user: [ThresholdSeal.Custodian], server: [ThresholdSeal.Custodian]) {
        ([ThresholdSeal.Custodian(label: "phone-se", institutional: false),
          ThresholdSeal.Custodian(label: "usb", institutional: false),
          ThresholdSeal.Custodian(label: "contact", institutional: false)],
         [ThresholdSeal.Custodian(label: "node-a", institutional: true),
          ThresholdSeal.Custodian(label: "node-b", institutional: true),
          ThresholdSeal.Custodian(label: "node-c", institutional: true)])
    }
}
