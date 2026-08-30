import Foundation

/// Governed index — who sets `colIndex` / `valueIndex` for the issuance engine.
/// Swift parity with `backend/atlas/economy/governance.py` (Python reference of record).
///
/// Not the company, not a single oracle: a VOTE of CERTIFIED NON-PROFITS, anchored to public global
/// references. The ratified value is the MEDIAN of the votes (robust to a captured/mistaken voter)
/// and requires a quorum. One vote per certified body (last submission wins). Decentralised
/// value-setting is also the securities-positive move: no single promoter decides value.

public enum QuorumError: Error, Equatable { case notEnoughVoters(need: Int, got: Int) }

public struct IndexVote: Equatable {
    public let voter: String   // a certified non-profit's id
    public let epoch: Int
    public let col: Int        // proposed cost-of-living index
    public let value: Int      // proposed token value index (bp of par)
    public init(voter: String, epoch: Int, col: Int, value: Int) {
        self.voter = voter; self.epoch = epoch; self.col = col; self.value = value
    }
}

/// Median with Python `//` semantics (floor). Even count averages the two middle values.
func economyMedian(_ xs: [Int]) -> Int {
    let s = xs.sorted()
    let n = s.count
    let mid = n / 2
    if n % 2 != 0 { return s[mid] }
    // floor division of the sum of the two middles (matches Python `(a+b)//2`)
    let sum = s[mid - 1] + s[mid]
    let q = sum / 2, r = sum % 2
    return (r != 0 && ((sum < 0) != (2 < 0))) ? q - 1 : q
}

/// Registry of certified non-profit voters + the ratification rule.
public final class IndexGovernance {
    public let quorum: Int
    private var certified: Set<String> = []

    public init(quorum: Int = 3) { self.quorum = quorum }

    public func certify(_ voter: String) { certified.insert(voter) }
    public func revoke(_ voter: String) { certified.remove(voter) }
    public func isCertified(_ voter: String) -> Bool { certified.contains(voter) }

    /// Return the ratified (colIndex, valueIndex) for `epoch`: the median across certified voters
    /// (one vote each — last submission wins). Throws if the quorum isn't met.
    public func ratify(_ votes: [IndexVote], epoch: Int) throws -> (Int, Int) {
        var valid: [String: IndexVote] = [:]
        for v in votes where v.epoch == epoch && certified.contains(v.voter) {
            valid[v.voter] = v          // dedupe: one vote per certified body
        }
        if valid.count < quorum { throw QuorumError.notEnoughVoters(need: quorum, got: valid.count) }
        let cols = valid.values.map { $0.col }
        let vals = valid.values.map { $0.value }
        return (economyMedian(cols), economyMedian(vals))
    }
}
