import Foundation

/// Distributed custody + rotation for the SERVER HALF of the two-tier TSK.
/// Swift parity with `backend/atlas/keys/server_custody.py` (Python reference of record).
///
/// `server_half` (independent of the seed; useless without a threshold of YOUR holders) is Shamir
/// k-of-m split across institutional NODES. Each node stores only an OPAQUE sealed blob, indexed by
/// a blinded locator `H(recovery_selector, node_id, epoch)`:
///  - BLIND: sealed under a per-locator key only the recovering user can re-derive.
///  - UNLINKABLE: the locator hides who/where; one user's shares are mutually unlinkable.
///  - USELESS-ALONE: a server-half share reveals nothing about the seed (XOR one-time-pad).
/// ROTATION re-shares to a fresh node set at a new epoch and retires ALL old locators, so no fixed
/// node set holds a usable share across a rotation.
public enum ServerCustody {

    public enum CustodyError: Error, Equatable { case thresholdNotMet, badPolicy, duplicateNode }

    public struct CustodianNode: Equatable {
        public let nodeID: String
        public init(nodeID: String) { self.nodeID = nodeID }
    }

    public struct CustodyPlacement: Equatable {
        public let nodeID: String
        public let locator: Data      // H(recovery_selector, node_id, epoch)
        public let blob: Data         // AEAD(sealKey(locator), share.encode(), aad: locator)
        public let epoch: Int
    }

    private static let locatorLabel = Data("atlas/custody/locator/v1".utf8)
    private static let sealLabel = Data("atlas/custody/seal/v1".utf8)

    static func locator(recoverySelector: Data, nodeID: String, epoch: Int) -> Data {
        var be = UInt32(epoch).bigEndian
        let epochBytes = withUnsafeBytes(of: &be) { Data($0) }
        return Primitives.H(locatorLabel, recoverySelector, Data(nodeID.utf8), epochBytes)
    }

    static func sealKey(recoveryKey: Data, locator: Data) -> Data {
        Primitives.hkdf(ikm: recoveryKey, info: sealLabel + locator, length: 32)
    }

    public static func distribute(
        serverHalf: Data,
        nodes: [CustodianNode],
        policy: ThresholdSeal.ThresholdPolicy,
        recoverySelector: Data,
        recoveryKey: Data,
        epoch: Int = 0
    ) throws -> [CustodyPlacement] {
        guard nodes.count == policy.n else { throw CustodyError.badPolicy }
        guard Set(nodes.map { $0.nodeID }).count == nodes.count else { throw CustodyError.duplicateNode }
        let raw = Shamir.split(serverHalf, n: policy.n, k: policy.m)
        return try zip(nodes, raw).map { node, share in
            let loc = locator(recoverySelector: recoverySelector, nodeID: node.nodeID, epoch: epoch)
            let blob = try Primitives.aeadEncrypt(key: sealKey(recoveryKey: recoveryKey, locator: loc),
                                                  plaintext: share.encode(), aad: loc)
            return CustodyPlacement(nodeID: node.nodeID, locator: loc, blob: blob, epoch: epoch)
        }
    }

    /// Open >= k retrieved (locator, blob) pairs and Shamir-combine back to server_half.
    public static func collect(
        retrieved: [(locator: Data, blob: Data)],
        policy: ThresholdSeal.ThresholdPolicy,
        recoveryKey: Data
    ) throws -> Data {
        guard retrieved.count >= policy.m else { throw CustodyError.thresholdNotMet }
        let shares = try retrieved.map { item -> Shamir.Share in
            let opened = try Primitives.aeadDecrypt(key: sealKey(recoveryKey: recoveryKey, locator: item.locator),
                                                    blob: item.blob, aad: item.locator)
            return Shamir.Share.decode(opened)
        }
        return Shamir.combine(shares)
    }

    /// Proactive re-share: reconstruct from >= k retrieved shares, re-split FRESH to `newNodes` at
    /// `newEpoch`. Returns (newPlacements, dropLocators) — dropping EVERY old locator so no stale
    /// share lingers. Reconstructing server_half never exposes the TSK (independent of the seed).
    public static func rotate(
        retrieved: [(locator: Data, blob: Data)],
        allOldLocators: [Data],
        policy: ThresholdSeal.ThresholdPolicy,
        recoverySelector: Data,
        recoveryKey: Data,
        newNodes: [CustodianNode],
        newEpoch: Int
    ) throws -> (newPlacements: [CustodyPlacement], dropLocators: [Data]) {
        let serverHalf = try collect(retrieved: retrieved, policy: policy, recoveryKey: recoveryKey)
        let newPlacements = try distribute(serverHalf: serverHalf, nodes: newNodes, policy: policy,
                                           recoverySelector: recoverySelector, recoveryKey: recoveryKey,
                                           epoch: newEpoch)
        return (newPlacements, allOldLocators)
    }
}
