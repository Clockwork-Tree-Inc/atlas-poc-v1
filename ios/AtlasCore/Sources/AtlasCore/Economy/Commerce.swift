import Foundation

/// Commerce over APLC — the marketplace as a storefront continuous with the real store.
/// Swift parity with `backend/atlas/economy/commerce.py` (Python reference of record).
///
/// Businesses list, accept the coin, and pay a per-sale fee + listing fee. Those fees ARE the
/// tithe: they route to the Foundation `tithe` account, which closes the loop into the issuance
/// engine (`Policy` draws that balance as `titheInflow`). Payments are on-ledger transfers
/// (buyer → seller), no new supply. Fees buy ACCESS, never RANK.

public enum Commerce {
    public static let defaultFeeBp = 300         // 3% per-sale tithe
    public static let titheAccount = "tithe"     // the Foundation pool the issuance engine draws from

    public enum CommerceError: Error, Equatable {
        case amountMustBePositive
        case slotAlreadyBooked
    }

    public struct Sale: Equatable {
        public let buyer: String
        public let seller: String
        public let item: Data
        public let amount: Int
        public let fee: Int          // routed to the Foundation tithe pool
        public let epoch: Int
    }

    public struct Booking: Equatable {
        public let buyer: String
        public let provider: String
        public let service: Data
        public let slot: String
        public let amount: Int
        public let fee: Int
        public let epoch: Int
    }

    static func fee(_ amount: Int, _ feeBp: Int) -> Int { amount * feeBp / 10_000 }

    /// Buyer pays `amount`: the per-sale fee goes to the tithe pool, the rest to the seller.
    public static func purchase(_ coin: Coin, buyer: String, seller: String, item: Data,
                                amount: Int, epoch: Int, feeBp: Int = defaultFeeBp,
                                titheAccount: String = titheAccount) throws -> Sale {
        if amount <= 0 { throw CommerceError.amountMustBePositive }
        if coin.balance(buyer) < amount { throw LedgerError.insufficientBalance }
        let f = fee(amount, feeBp)
        try coin.transfer(buyer, titheAccount, f)        // tithe first (funds UBI next epoch)
        try coin.transfer(buyer, seller, amount - f)
        return Sale(buyer: buyer, seller: seller, item: item, amount: amount, fee: f, epoch: epoch)
    }

    /// A periodic listing/membership fee — access to being surfaced (never rank). Also tithe.
    @discardableResult
    public static func payListingFee(_ coin: Coin, business: String, amount: Int,
                                     titheAccount: String = titheAccount) throws -> Int {
        if amount <= 0 { throw CommerceError.amountMustBePositive }
        try coin.transfer(business, titheAccount, amount)
        return amount
    }

    /// Slot reservations for services. One (provider, service, slot) can be booked once; booking
    /// pays with the same per-sale tithe as a purchase.
    public final class BookingBook {
        private var taken: Set<String> = []
        public init() {}

        private func key(_ provider: String, _ service: Data, _ slot: String) -> String {
            provider + "\u{0}" + service.map { String(format: "%02x", $0) }.joined() + "\u{0}" + slot
        }

        public func isFree(_ provider: String, _ service: Data, _ slot: String) -> Bool {
            !taken.contains(key(provider, service, slot))
        }

        public func book(_ coin: Coin, buyer: String, provider: String, service: Data, slot: String,
                         amount: Int, epoch: Int, feeBp: Int = defaultFeeBp,
                         titheAccount: String = titheAccount) throws -> Booking {
            if amount <= 0 { throw CommerceError.amountMustBePositive }
            let k = key(provider, service, slot)
            if taken.contains(k) { throw CommerceError.slotAlreadyBooked }
            if coin.balance(buyer) < amount { throw LedgerError.insufficientBalance }
            let f = fee(amount, feeBp)
            try coin.transfer(buyer, titheAccount, f)
            try coin.transfer(buyer, provider, amount - f)
            taken.insert(k)
            return Booking(buyer: buyer, provider: provider, service: service, slot: slot,
                           amount: amount, fee: f, epoch: epoch)
        }
    }
}
