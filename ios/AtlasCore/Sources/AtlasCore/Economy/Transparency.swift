import Foundation

/// Organization transparency — privacy for people, accountability for businesses.
/// Swift parity with `backend/atlas/economy/transparency.py` (Python reference of record).
///
/// Individuals stay private (unlinkable personas, private transfers). BUSINESSES must operate in
/// the open: to trade commercially a business must be IDENTIFIED, and every commercial action is
/// written to an append-only, hash-chained, PUBLICLY AUDITABLE ledger. The customer on the other
/// side stays pseudonymous. Privacy, not piracy.
///
/// DIGEST-PARITY NOTE: this port replicates the tamper-evident chaining + identity gating LOGIC.
/// For the chain digest it uses AtlasCore's `Primitives.H` (SHA3-256) over the SAME length-prefixed
/// framing as the Python reference's `_h`, so the digests happen to be byte-identical here — but
/// per the task, byte-identity is NOT a required invariant for this module; the load-bearing
/// property is that any edit/reorder/deletion breaks `verifyChain`.

public enum IdentityRequiredError: Error, Equatable { case notIdentified }

public enum Transparency {
    static let zero = Data(count: 32)

    /// Length-prefixed framing identical to Python `_h`: for each part, 4-byte big-endian length
    /// then the part, all fed to SHA3-256 via `Primitives.H`.
    static func h(_ parts: [Data]) -> Data {
        var buf = Data()
        for p in parts {
            var n = UInt32(p.count).bigEndian
            withUnsafeBytes(of: &n) { buf.append(contentsOf: $0) }
            buf.append(p)
        }
        return Primitives.H(buf)
    }

    private static func be8(_ v: Int) -> Data {
        var n = UInt64(bitPattern: Int64(v)).bigEndian
        return withUnsafeBytes(of: &n) { Data($0) }
    }

    public struct Entry: Equatable {
        public let business: String    // IDENTIFIED business id — never a private persona
        public let kind: String        // "sale" | "listing_fee" | "booking"
        public let amount: Int
        public let fee: Int            // the tithe portion
        public let counterparty: String  // MAY be a pseudonym — customer privacy is preserved
        public let epoch: Int
        public let prev: Data          // hash-chain link (tamper-evidence)

        public func digest() -> Data {
            h([Data("atlas/txlog".utf8), Data(business.utf8), Data(kind.utf8),
               be8(amount), be8(fee), Data(counterparty.utf8), be8(epoch), prev])
        }
    }

    /// Append-only, hash-chained, publicly auditable record of business commercial activity.
    public final class TransparencyLedger {
        private var entries: [Entry] = []
        private var identified: Set<String> = []
        public init() {}

        /// Admit a business. It MUST be identified — anonymous commercial operation is refused.
        public func registerBusiness(_ business: String, identified: Bool) throws {
            if !identified { throw IdentityRequiredError.notIdentified }
            self.identified.insert(business)
        }

        public func isIdentified(_ business: String) -> Bool { identified.contains(business) }

        /// The chain head — the public ROOT to anchor. Publishing this immutably checkpoints the
        /// books up to now WITHOUT revealing any entry (a hash, not content). Mirrors Python's
        /// public `head()`.
        public func head() -> Data { entries.last?.digest() ?? zero }

        @discardableResult
        public func record(business: String, kind: String, amount: Int, fee: Int,
                           counterparty: String, epoch: Int) throws -> Entry {
            if !identified.contains(business) { throw IdentityRequiredError.notIdentified }
            let e = Entry(business: business, kind: kind, amount: amount, fee: fee,
                          counterparty: counterparty, epoch: epoch, prev: head())
            entries.append(e)
            return e
        }

        /// Public audit: every entry, or one business's full books. Nothing is hidden.
        public func audit(_ business: String? = nil) -> [Entry] {
            entries.filter { business == nil || $0.business == business }
        }

        /// The books are tamper-evident: any edit/reorder/deletion breaks the chain.
        public func verifyChain() -> Bool {
            var prev = zero
            for e in entries {
                if e.prev != prev { return false }
                prev = e.digest()
            }
            return true
        }

        /// Test/tamper hook: replace an entry in place (used to prove `verifyChain` catches edits).
        func tamper(at index: Int, with entry: Entry) { entries[index] = entry }
    }

    /// A business sells to a (pseudonymous) customer: run the APLC purchase AND record the business
    /// side transparently. The seller must be an identified business; the buyer stays private.
    @discardableResult
    public static func businessSale(_ coin: Coin, _ ledger: TransparencyLedger, seller: String,
                                    buyer: String, item: Data, amount: Int, epoch: Int,
                                    feeBp: Int = Commerce.defaultFeeBp) throws -> Commerce.Sale {
        if !ledger.isIdentified(seller) { throw IdentityRequiredError.notIdentified }
        let sale = try Commerce.purchase(coin, buyer: buyer, seller: seller, item: item,
                                         amount: amount, epoch: epoch, feeBp: feeBp)
        try ledger.record(business: seller, kind: "sale", amount: sale.amount, fee: sale.fee,
                          counterparty: buyer, epoch: epoch)
        return sale
    }

    /// A business pays its listing/membership fee (→ tithe) and it is recorded transparently.
    @discardableResult
    public static func businessListingFee(_ coin: Coin, _ ledger: TransparencyLedger,
                                          business: String, amount: Int, epoch: Int) throws -> Int {
        if !ledger.isIdentified(business) { throw IdentityRequiredError.notIdentified }
        let paid = try Commerce.payListingFee(coin, business: business, amount: amount)
        try ledger.record(business: business, kind: "listing_fee", amount: paid, fee: paid,
                          counterparty: "foundation", epoch: epoch)
        return paid
    }
}
