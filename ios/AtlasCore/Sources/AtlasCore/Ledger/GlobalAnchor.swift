import Foundation

/// Global anchoring of individual-ledger roots (TRUST_LAYER.md #8). Mirrors
/// `backend/atlas/ledger/global_anchor.py`. Per-owner roots are checkpointed here, each bound
/// to a drand round (the decentralized timekeeper). Only commitments (roots) are anchored —
/// never content. Tamper-evident append-only chain (PoC stand-in for drand/beacon + chain).
public struct GlobalReceipt {
    public let index: Int
    public let ownerID: Data
    public let anchoredRoot: Data
    public let drandRound: Data
    public let entryHash: Data
    public let prevHash: Data
}

public final class GlobalAnchorLog {
    public enum AnchorError: Error, Equatable { case backdated }

    public static let genesis = Data(repeating: 0, count: 32)
    static let label = Data("atlas/global-anchor".utf8)
    private var entries: [GlobalReceipt] = []
    private var lastRound: UInt64 = 0

    public init() {}

    public var head: Data { entries.last?.entryHash ?? Self.genesis }

    static func lp(_ d: Data) -> Data {
        var n = UInt32(d.count).bigEndian
        return withUnsafeBytes(of: &n) { Data($0) } + d
    }

    @discardableResult
    public func anchor(ownerID: Data, root: Data, drandRound: Data) throws -> GlobalReceipt {
        let round = drandRound.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }  // big-endian -> UInt64
        if !entries.isEmpty && round < lastRound { throw AnchorError.backdated }
        let prev = head
        let idx = entries.count
        var ib = UInt64(idx).bigEndian
        let entryHash = Primitives.H(Self.label, prev, Self.lp(ownerID), Self.lp(root),
                                     Self.lp(drandRound), withUnsafeBytes(of: &ib) { Data($0) })
        let r = GlobalReceipt(index: idx, ownerID: ownerID, anchoredRoot: root,
                              drandRound: drandRound, entryHash: entryHash, prevHash: prev)
        entries.append(r)
        lastRound = round
        return r
    }

    /// The most recently anchored root for `ownerID` (nil if never anchored).
    public func latestRoot(_ ownerID: Data) -> Data? {
        entries.last(where: { $0.ownerID == ownerID })?.anchoredRoot
    }

    /// Was this exact `(ownerID, root)` ever checkpointed here?
    public func isAnchored(ownerID: Data, root: Data) -> Bool {
        entries.contains { $0.ownerID == ownerID && $0.anchoredRoot == root }
    }

    public func verifyChain() -> Bool {
        var prev = Self.genesis
        var lastRoundSeen: UInt64? = nil
        for (i, e) in entries.enumerated() {
            var ib = UInt64(i).bigEndian
            let expect = Primitives.H(Self.label, prev, Self.lp(e.ownerID), Self.lp(e.anchoredRoot),
                                      Self.lp(e.drandRound), withUnsafeBytes(of: &ib) { Data($0) })
            if e.entryHash != expect || e.prevHash != prev || e.index != i { return false }
            // D2 parity: re-derive drand-round monotonicity too, so a hand-built hash-consistent
            // chain with REWOUND rounds does not verify (mirrors global_anchor.py verify_chain).
            let round = e.drandRound.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
            if let last = lastRoundSeen, round < last { return false }
            lastRoundSeen = round
            prev = e.entryHash
        }
        return true
    }
}
