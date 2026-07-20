import Foundation

/// Per-user / per-space append-only ledger of COMMITMENTS (TRUST_LAYER.md #8). Mirrors
/// `backend/atlas/ledger/individual.py`. Holds only commitments (hiding+binding hashes of
/// content), never content; the Merkle `root` is what the global anchor publishes.
public enum LedgerCommit {
    static let label = Data("atlas/ledger-commit".utf8)

    /// `(commitment, opening)`. Pass `opening` to reproduce a known commitment (verification);
    /// omit it to mint a fresh HIDING commitment. Commitment = H(label, opening, content).
    public static func commit(_ content: Data, opening: Data? = nil) -> (commitment: Data, opening: Data) {
        let o = opening ?? Primitives.randomBytes(32)
        return (Primitives.H(label, o, content), o)
    }
}

/// A compact proof that `commitment` (at `index`) is under `root`.
public struct InclusionProof {
    public let commitment: Data
    public let index: Int
    public let path: [Merkle.ProofStep]
    public let root: Data
    public func verify() -> Bool { Merkle.verifyInclusion(commitment, proof: path, root: root) }
}

public final class IndividualLedger {
    public let ownerID: Data
    private var leaves: [Data] = []

    public init(ownerID: Data) { self.ownerID = ownerID }

    /// Append a commitment (never content); returns its leaf index.
    @discardableResult public func append(_ commitment: Data) -> Int {
        leaves.append(commitment)
        return leaves.count - 1
    }

    public var count: Int { leaves.count }
    /// Current Merkle root — the commitment to anchor globally.
    public var root: Data { Merkle.root(leaves) }
    public func contains(_ commitment: Data) -> Bool { leaves.contains(commitment) }

    /// Inclusion proof for the leaf at `index`, against the CURRENT root.
    public func prove(_ index: Int) -> InclusionProof {
        precondition(index >= 0 && index < leaves.count, "leaf index out of range")
        return InclusionProof(commitment: leaves[index], index: index,
                              path: Merkle.inclusionProof(leaves, index: index), root: root)
    }
}
