import Foundation

/// Ledger-anchored re-root — compromise recovery (the FUTURE half of A13). Mirrors
/// `backend/atlas/authority/reroot.py`. A re-root is authorized by an INDEPENDENT recovery key (not
/// the compromised forward-secure signing key) and anchored (unforgeable cutover). After it, the old
/// root is retired: verification runs against the current root, so old-root grants no longer verify.
extension Authority {

    static let rerootDomain = Data("atlas/authority/reroot/v1".utf8)

    public struct ReRoot {
        public var resource: Data
        public var newRoot: FSSign.FSPublicKey
        public var effectiveEpoch: UInt64
        public var sig: Data = Data()
        public init(resource: Data, newRoot: FSSign.FSPublicKey, effectiveEpoch: UInt64, sig: Data = Data()) {
            self.resource = resource; self.newRoot = newRoot; self.effectiveEpoch = effectiveEpoch; self.sig = sig
        }
        public func body() -> Data {
            Authority.rerootDomain + Authority.lp(resource) + Authority.lp(newRoot.root)
                + Authority.u32(newRoot.height) + Authority.u64(effectiveEpoch)
        }
    }

    public static func makeReroot(_ recovery: HybridSign.Keypair, resource: Data,
                                  newRoot: FSSign.FSPublicKey, effectiveEpoch: UInt64) throws -> ReRoot {
        var r = ReRoot(resource: resource, newRoot: newRoot, effectiveEpoch: effectiveEpoch)
        r.sig = try HybridSign.sign(recovery, r.body())
        return r
    }

    /// The FS root that currently controls `resource`: the latest valid recovery-signed re-root (by
    /// effective epoch), or `genesisRoot`. A re-root not signed by `recoveryPublic` is ignored.
    public static func currentRoot(_ resource: Data, recoveryPublic: HybridSign.PublicKey,
                                   genesisRoot: FSSign.FSPublicKey, reroots: [ReRoot]) -> FSSign.FSPublicKey {
        let valid = reroots
            .filter { $0.resource == resource && HybridSign.verify(recoveryPublic, $0.body(), $0.sig) }
            .sorted { $0.effectiveEpoch < $1.effectiveEpoch }
        return valid.last?.newRoot ?? genesisRoot
    }
}
