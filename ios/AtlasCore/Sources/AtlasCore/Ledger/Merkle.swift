import Foundation

/// Binary Merkle tree over commitments (TRUST_LAYER.md #8). Mirrors
/// `backend/atlas/ledger/merkle.py` byte-for-byte (domain-separated leaf/node hashing,
/// odd nodes promoted unchanged). Compact O(log n) inclusion proofs for selective disclosure.
public enum Merkle {
    /// One proof step: the sibling hash and whether it sits to the RIGHT of the running hash.
    public typealias ProofStep = (sibling: Data, siblingIsRight: Bool)

    static let leafLabel = Data("atlas/merkle-leaf".utf8)
    static let nodeLabel = Data("atlas/merkle-node".utf8)
    static let emptyLabel = Data("atlas/merkle-empty".utf8)

    public static func leafHash(_ commitment: Data) -> Data { Primitives.H(leafLabel, commitment) }
    static func node(_ l: Data, _ r: Data) -> Data { Primitives.H(nodeLabel, l, r) }
    public static func emptyRoot() -> Data { Primitives.H(emptyLabel) }

    public static func root(_ leaves: [Data]) -> Data {
        if leaves.isEmpty { return emptyRoot() }
        var level = leaves.map { leafHash($0) }
        while level.count > 1 { level = nextLevel(level) }
        return level[0]
    }

    public static func inclusionProof(_ leaves: [Data], index: Int) -> [ProofStep] {
        precondition(index >= 0 && index < leaves.count, "leaf index out of range")
        var level = leaves.map { leafHash($0) }
        var idx = index
        var proof: [ProofStep] = []
        while level.count > 1 {
            let sib = idx ^ 1
            if sib < level.count { proof.append((level[sib], sib > idx)) }
            level = nextLevel(level)
            idx /= 2
        }
        return proof
    }

    public static func verifyInclusion(_ commitment: Data, proof: [ProofStep], root: Data) -> Bool {
        var h = leafHash(commitment)
        for step in proof { h = step.siblingIsRight ? node(h, step.sibling) : node(step.sibling, h) }
        return h == root
    }

    private static func nextLevel(_ level: [Data]) -> [Data] {
        var nxt: [Data] = []
        var i = 0
        while i < level.count {
            if i + 1 < level.count { nxt.append(node(level[i], level[i + 1])); i += 2 }
            else { nxt.append(level[i]); i += 1 }   // promote odd node unchanged
        }
        return nxt
    }
}
