import Foundation

/// Fiat on-ramp — ONE-WAY, closed-loop. Swift parity with `backend/atlas/economy/onramp.py`.
///
/// Users bring REAL money IN and receive APLC to spend inside Atlas. The coin is Atlas-world-only:
/// it never cashes out to fiat — there is deliberately no reverse function anywhere (that makes
/// APLC closed-loop stored value, not open-loop transmittable money). The fiat received is held by
/// the Foundation as a RESERVE backing the coin's internal purchasing power; the APLC minted is
/// fully reserve-backed and never targets a company account.

public enum OnrampError: Error, Equatable {
    case fiatAmountMustBePositive
    case rateMustBePositive
}

/// Foundation-held fiat received via the on-ramp, in minor units (e.g. cents), per currency.
public final class FiatReserve {
    private var held_: [String: Int] = [:]
    public init() {}

    public func held(_ currency: String) -> Int { held_[currency] ?? 0 }

    func add(_ currency: String, _ amount: Int) { held_[currency] = held(currency) + amount }
}

/// Bring fiat IN → receive APLC to spend inside Atlas. Fiat goes to the Foundation reserve
/// (backing); the APLC minted is fully reserve-backed. Returns the APLC credited.
///
/// There is intentionally NO reverse — the closed loop is STRUCTURAL: the absence of a
/// redeem/withdraw path is the compliance property, not a runtime check. See `Redemption`.
@discardableResult
public func depositFiat(_ coin: Coin, _ reserve: FiatReserve, buyer: String, fiatAmount: Int,
                        currency: String, aplcPerFiat: Int) throws -> Int {
    if fiatAmount <= 0 { throw OnrampError.fiatAmountMustBePositive }
    if aplcPerFiat <= 0 { throw OnrampError.rateMustBePositive }
    let aplc = fiatAmount * aplcPerFiat
    reserve.add(currency, fiatAmount)   // fiat held as backing
    try coin.mint(buyer, aplc)          // reserve-backed mint to the buyer (never a company account)
    return aplc
}

// NOTE: there is deliberately no withdrawFiat / redeemToFiat / cashOut. APLC is Atlas-world-only.
// Do not add one without counsel — it would convert a closed-loop stored-value system into
// open-loop money transmission.
