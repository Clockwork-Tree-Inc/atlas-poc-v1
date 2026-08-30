import Foundation

/// Global anchoring of individual-ledger roots (TRUST_LAYER.md #8). Mirrors
/// `backend/atlas/ledger/global_anchor.py` byte-for-byte. An append-only, tamper-evident hash
/// chain of `(owner_id, root, epoch_round)` checkpoints — only commitments (roots) are
/// anchored, never content. drand rounds are forced NON-DECREASING (no backdating). Altering
/// any past anchor breaks every later `entryHash`.
///
/// HONEST BOUNDARY: this single local chain is tamper-EVIDENT but does not by itself prevent
/// EQUIVOCATION (two divergent chains shown to different parties). Non-equivocation needs the
/// real decentralized substrate (drand beacon + public blockchain + satellite checkpoints).
public enum GlobalAnchor {
    fileprivate static let domain = Data("atlas/global-anchor".utf8)
    public static let genesis = Data(repeating: 0, count: 32)

    fileprivate static func lp(_ b: Data) -> Data {
        var n = UInt32(b.count).bigEndian
        return withUnsafeBytes(of: &n) { Data($0) } + b
    }
    fileprivate static func u64(_ v: UInt64) -> Data {
        var n = v.bigEndian; return withUnsafeBytes(of: &n) { Data($0) }
    }
    /// Big-endian Data -> Int for the monotonic round check (drand rounds are ≤ 8 bytes).
    fileprivate static func roundValue(_ d: Data) -> Int {
        var v = 0
        for b in d { v = (v << 8) | Int(b) }
        return v
    }

    public struct Receipt: Equatable {
        public let index: Int
        public let ownerID: Data
        public let anchoredRoot: Data      // the individual ledger's Merkle root at anchor time
        public let epochRound: Data        // decentralized timekeeper binding
        public let entryHash: Data
        public let prevHash: Data
    }

    public enum AnchorError: Error, Equatable { case backdatedRound }

    /// Append-only chain of `(owner_id, root, epoch_round)` checkpoints.
    public final class Log {
        private var entries: [Receipt] = []
        private var lastRound = -1
        public init() {}

        public var head: Data { entries.last?.entryHash ?? GlobalAnchor.genesis }
        public var count: Int { entries.count }

        public func anchor(ownerID: Data, root: Data, epochRound: Data) throws -> Receipt {
            // drand rounds only move forward — reject a backdated (non-monotonic) round.
            let r = GlobalAnchor.roundValue(epochRound)
            if !entries.isEmpty && r < lastRound { throw AnchorError.backdatedRound }
            let prev = head
            let idx = entries.count
            // length-prefix EVERY variable-length field so no byte migrates across a boundary.
            let entryHash = Primitives.H(GlobalAnchor.domain, prev, GlobalAnchor.lp(ownerID),
                                         GlobalAnchor.lp(root), GlobalAnchor.lp(epochRound),
                                         GlobalAnchor.u64(UInt64(idx)))
            let receipt = Receipt(index: idx, ownerID: ownerID, anchoredRoot: root,
                                  epochRound: epochRound, entryHash: entryHash, prevHash: prev)
            entries.append(receipt)
            lastRound = r
            return receipt
        }

        /// The most recently anchored root for `ownerID` (nil if never anchored).
        public func latestRoot(ownerID: Data) -> Data? {
            entries.reversed().first { $0.ownerID == ownerID }?.anchoredRoot
        }

        /// Was this exact `(ownerID, root)` ever checkpointed here?
        public func isAnchored(ownerID: Data, root: Data) -> Bool {
            entries.contains { $0.ownerID == ownerID && $0.anchoredRoot == root }
        }

        /// Re-derive EVERY property the append path enforces (hash chain, index, AND
        /// non-decreasing rounds) — so a producer can't hand-build a hash-consistent chain with
        /// rewound rounds and have it verify.
        public func verifyChain() -> Bool {
            var prev = GlobalAnchor.genesis
            var last = -1
            for (i, e) in entries.enumerated() {
                let expect = Primitives.H(GlobalAnchor.domain, prev, GlobalAnchor.lp(e.ownerID),
                                          GlobalAnchor.lp(e.anchoredRoot), GlobalAnchor.lp(e.epochRound),
                                          GlobalAnchor.u64(UInt64(i)))
                if e.entryHash != expect || e.prevHash != prev || e.index != i { return false }
                let r = GlobalAnchor.roundValue(e.epochRound)
                if r < last { return false }
                last = r
                prev = e.entryHash
            }
            return true
        }
    }
}
