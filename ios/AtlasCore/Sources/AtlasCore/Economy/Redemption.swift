import Foundation

/// Redemption gate — the (currently CLOSED) fiat off-ramp seam.
/// Swift parity with `backend/atlas/economy/redemption.py` (Python reference of record).
///
/// APLC is Atlas-world-only TODAY (see `Onramp`: fiat in, no cash-out). The design anticipates
/// OPENING a fiat off-ramp LATER — but only once (1) money-transmitter/e-money licensing + KYC/AML
/// are in place, (2) the coin has organic utility value and is decentralised, and (3) the reserve
/// can honour redemptions. Opening is then a MODULE SWAP behind this gate (`ClosedLoop` →
/// `FiatRedemption`), gated behind counsel + governance.

public enum ClosedLoopError: Error, Equatable {
    case offRampClosed        // any attempt to cash out while the off-ramp is closed (the default)
    case notImplemented       // the future open state — a stub, not a TODO
}

public protocol RedemptionGate {
    func redeem(_ coin: Coin, _ reserve: FiatReserve, holder: String,
                aplcAmount: Int, currency: String) throws -> Int
}

/// DEFAULT — no off-ramp. APLC never leaves the Atlas world.
public struct ClosedLoop: RedemptionGate {
    public init() {}
    public func redeem(_ coin: Coin, _ reserve: FiatReserve, holder: String,
                       aplcAmount: Int, currency: String) throws -> Int {
        throw ClosedLoopError.offRampClosed
    }
}

/// STUB for the future open state. Do NOT implement without counsel: a real version must gate on
/// licensing + KYC/AML on the holder, verify reserve adequacy before paying out, and be enabled by
/// governance. Its mere existence is money transmission — that is why it is a stub, not a TODO.
public struct FiatRedemption: RedemptionGate {
    public init() {}
    public func redeem(_ coin: Coin, _ reserve: FiatReserve, holder: String,
                       aplcAmount: Int, currency: String) throws -> Int {
        throw ClosedLoopError.notImplemented
    }
}
