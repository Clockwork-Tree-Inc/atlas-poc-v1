import Foundation

/// Forward-secure ratcheted signer — mirrors `backend/atlas/authority/fs_sign.py` byte-for-byte on
/// the Merkle glue. The A13 structural fix: one fixed public key (a Merkle root over N = 2**height
/// per-epoch leaves); the signer holds only the current epoch's state and `advance()` ratchets one-way
/// (H), DESTROYING the past — so a compromised current signer cannot reconstruct a past leaf's secret
/// to backdate. The epoch is intrinsic to the leaf's tree position, not a self-asserted field.
public enum FSSign {

    static let leafSeedDom = Data("atlas/fs/leaf-seed".utf8)
    static let stateNextDom = Data("atlas/fs/state-next".utf8)
    static let leafDom = Data("atlas/fs/leaf".utf8)
    static let nodeDom = Data("atlas/fs/node".utf8)
    static let genesisDom = Data("atlas/fs/genesis".utf8)

    public enum FSError: Error, Equatable { case fail(String) }

    static func leafSeed(_ s: Data) -> Data { Primitives.H(leafSeedDom, s) }
    static func nextState(_ s: Data) -> Data { Primitives.H(stateNextDom, s) }
    static func leafHash(_ leafPubEnc: Data) -> Data { Primitives.H(leafDom, leafPubEnc) }
    static func node(_ l: Data, _ r: Data) -> Data { Primitives.H(nodeDom, l, r) }

    public struct FSPublicKey: Equatable {
        public let root: Data
        public let height: Int
        public init(root: Data, height: Int) { self.root = root; self.height = height }
    }

    public struct FSSignature {
        public let epoch: Int
        public let leafPublic: Data
        public let sig: Data
        public let authPath: [Data]
    }

    // MARK: - merkle

    static func levels(_ leafHashes: [Data]) -> [[Data]] {
        var out = [leafHashes]
        var cur = leafHashes
        while cur.count > 1 {
            var nxt = [Data]()
            var i = 0
            while i < cur.count { nxt.append(node(cur[i], cur[i + 1])); i += 2 }
            out.append(nxt); cur = nxt
        }
        return out
    }
    static func authPath(_ levels: [[Data]], _ index: Int) -> [Data] {
        var path = [Data](); var idx = index
        for level in levels.dropLast() { path.append(level[idx ^ 1]); idx /= 2 }
        return path
    }
    public static func rootFromPath(_ leafHash: Data, _ index: Int, _ path: [Data]) -> Data {
        var h = leafHash; var idx = index
        for sib in path { h = (idx & 1 == 0) ? node(h, sib) : node(sib, h); idx /= 2 }
        return h
    }

    // MARK: - signer

    public final class FSSigner {
        let levels: [[Data]]
        let n: Int
        public private(set) var epoch: Int
        var state: Data

        init(levels: [[Data]], n: Int, index: Int, state: Data) {
            self.levels = levels; self.n = n; self.epoch = index; self.state = state
        }

        public func publicKey() -> FSPublicKey { FSPublicKey(root: levels.last![0], height: levels.count - 1) }

        public func sign(_ message: Data) throws -> FSSignature {
            if epoch >= n { throw FSError.fail("forward-secure signer exhausted — re-root") }
            let leaf = try HybridSign.keypair(fromSeed: FSSign.leafSeed(state))
            return FSSignature(epoch: epoch, leafPublic: leaf.publicKey.encode(),
                               sig: try HybridSign.sign(leaf, message), authPath: FSSign.authPath(levels, epoch))
        }

        public func advance() throws {
            if epoch >= n { throw FSError.fail("cannot advance past the last epoch — re-root") }
            state = FSSign.nextState(state)      // one-way: the current secret state is now unrecoverable
            epoch += 1
        }
    }

    public static func keygen(seed: Data, height: Int = 4) throws -> (FSPublicKey, FSSigner) {
        if height < 1 { throw FSError.fail("height must be >= 1") }
        let n = 1 << height
        var state = Primitives.H(genesisDom, seed)
        let genesis = state
        var leafHashes = [Data]()
        for _ in 0..<n {
            let leafPub = try HybridSign.keypair(fromSeed: leafSeed(state)).publicKey.encode()
            leafHashes.append(leafHash(leafPub))
            state = nextState(state)
        }
        let lv = levels(leafHashes)
        let signer = FSSigner(levels: lv, n: n, index: 0, state: genesis)
        return (signer.publicKey(), signer)
    }

    public static func verify(_ pub: FSPublicKey, _ message: Data, _ signature: FSSignature) -> Bool {
        let n = 1 << pub.height
        guard signature.epoch >= 0, signature.epoch < n, signature.authPath.count == pub.height else { return false }
        guard let leafPub = HybridSign.PublicKey(encoded: signature.leafPublic) else { return false }
        guard HybridSign.verify(leafPub, message, signature.sig) else { return false }
        return rootFromPath(leafHash(signature.leafPublic), signature.epoch, signature.authPath) == pub.root
    }
}
