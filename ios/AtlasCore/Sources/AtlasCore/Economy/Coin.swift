import Foundation

/// Atlas PoLE coin (APLC) — the transferable, divisible value token.
/// Swift parity with `backend/atlas/economy/coin.py` (Python reference of record).
///
/// Run ENTIRELY by the FOUNDATION so value reaches people, not a company: there is NO
/// company/founder account and NO premine; coin is EARNED-ONLY (it enters circulation solely
/// via `Policy` issuance); the protocol sets no price. There is no public mint — only the
/// issuance path (`Policy.applyIssuance`) reaches `mint`. Integer base units only (no floats).
public enum Coins {
    public static let ticker = "APLC"
    public static let name = "Atlas PoLE coin"
    public static let foundation = "foundation"  // running-costs + charitable pool; NOT company profit

    /// A holder account derived from a person's unlinkable tag. There is deliberately no
    /// 'company' account constructor anywhere.
    public static func accountFor(_ personTag: Data) -> String {
        "p:" + personTag.map { String(format: "%02x", $0) }.joined()
    }
}

public enum LedgerError: Error, Equatable {
    case amountMustBePositive
    case insufficientBalance
    case cannotMintNegative
}

/// The APLC ledger — integer base units (no floats), transferable + divisible.
public final class Coin {
    private var bal: [String: Int] = [:]
    public private(set) var supply: Int = 0

    public init() {}

    public func balance(_ account: String) -> Int { bal[account] ?? 0 }

    /// Every non-zero account balance.
    public func accounts() -> [String: Int] { bal.filter { $0.value != 0 } }

    public func transfer(_ frm: String, _ to: String, _ amount: Int) throws {
        if amount <= 0 { throw LedgerError.amountMustBePositive }
        if balance(frm) < amount { throw LedgerError.insufficientBalance }
        if frm == to { return }
        bal[frm] = balance(frm) - amount
        bal[to] = balance(to) + amount
    }

    /// INTERNAL earned-only mint — reached only through the issuance path. No company account is
    /// ever a target; the only non-person target is the Foundation pool. Marked with a leading
    /// underscore-equivalent (`mint`) but kept `internal` so app code cannot call it directly.
    func mint(_ to: String, _ amount: Int) throws {
        if amount < 0 { throw LedgerError.cannotMintNegative }
        if amount == 0 { return }
        bal[to] = balance(to) + amount
        supply += amount
    }
}
