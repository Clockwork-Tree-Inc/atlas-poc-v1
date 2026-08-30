import Foundation

/// Issuance policy — the APLC monetary engine, run by the Foundation.
/// Swift parity with `backend/atlas/economy/policy.py` (Python reference of record).
///
/// Per epoch, from the aggregated PoLE pool and two GOVERNED signals (`colIndex`, `valueIndex`),
/// the business tithe funds distributions FIRST (backing the currency, reducing minting) and only
/// the shortfall is MINTED, bounded by a supply-growth cap. UBI is the sacrosanct floor — always
/// fully funded (tithe then mint) even past the cap (raising an emergency control flag). Variable
/// rewards + the Foundation pool are the capped, discretionary remainder.
///
/// All arithmetic is INTEGER: operands here are non-negative so Swift `/` matches Python `//`.

public enum PolicyError: Error, Equatable {
    case valueIndexMustBePositive
    case titheInflowMustBeNonNegative
}

public struct PolicyParams: Equatable {
    public var ubiShareBp: Int
    public var vrpShareBp: Int
    public var foundationShareBp: Int
    public var maxSupplyGrowthBp: Int   // hyperinflation guard: <=5% NEW supply / epoch
    public var scale: Int               // bp baseline (10 000 = par)

    public init(ubiShareBp: Int = 2000, vrpShareBp: Int = 7000, foundationShareBp: Int = 1000,
                maxSupplyGrowthBp: Int = 500, scale: Int = 10_000) {
        self.ubiShareBp = ubiShareBp; self.vrpShareBp = vrpShareBp
        self.foundationShareBp = foundationShareBp; self.maxSupplyGrowthBp = maxSupplyGrowthBp
        self.scale = scale
    }
}

public struct EconomyState: Equatable {
    public var supply: Int
    public init(supply: Int = 0) { self.supply = supply }
}

public struct IssuanceResult: Equatable {
    public let epoch: Int
    public let persons: Int
    public let ubiPerPerson: Int
    public let ubiTotal: Int
    public let vrpTotal: Int
    public let foundationTotal: Int
    public let titheUsed: Int      // funded by real business revenue (no new supply)
    public let minted: Int         // newly created supply (the shortfall after tithe)
    public let controls: [String]
    public let newSupply: Int
}

public enum Policy {
    public static func issue(_ pool: PoLEPool, colIndex: Int, valueIndex: Int,
                             titheInflow: Int = 0, state: EconomyState,
                             params: PolicyParams = PolicyParams()) throws -> IssuanceResult {
        if valueIndex <= 0 { throw PolicyError.valueIndexMustBePositive }
        if titheInflow < 0 { throw PolicyError.titheInflowMustBeNonNegative }

        let persons = pool.persons
        let ubiPerPerson = colIndex * params.scale / valueIndex   // real floor / token value
        let ubiTotal = ubiPerPerson * persons
        let nonUbiTarget = ubiTotal * (params.vrpShareBp + params.foundationShareBp)
            / max(params.ubiShareBp, 1)

        let cap = state.supply * params.maxSupplyGrowthBp / params.scale  // max NEW supply (0 at genesis)

        // UBI floor is sacrosanct: fund from tithe first, mint the rest (even past the cap → flag).
        let titheForUbi = min(titheInflow, ubiTotal)
        let ubiMinted = ubiTotal - titheForUbi
        let titheLeft = titheInflow - titheForUbi

        // Discretionary (VRP + Foundation): leftover tithe first, then remaining mint headroom.
        let mintHeadroom = max(0, cap - ubiMinted)
        let discretionary = min(nonUbiTarget, titheLeft + mintHeadroom)
        let discFromTithe = min(titheLeft, discretionary)
        let discMinted = discretionary - discFromTithe

        let denom = params.vrpShareBp + params.foundationShareBp
        let vrpTotal = denom != 0 ? discretionary * params.vrpShareBp / denom : 0
        let foundationTotal = discretionary - vrpTotal

        let minted = ubiMinted + discMinted
        let titheUsed = titheForUbi + discFromTithe

        var controls: [String] = []
        if discretionary < nonUbiTarget { controls.append("vrp_throttled") }
        if state.supply > 0 && ubiMinted > cap { controls.append("ubi_exceeds_growth_cap") }
        if valueIndex < params.scale { controls.append("value_below_par") }
        if titheInflow > 0 { controls.append("tithe_backed") }

        return IssuanceResult(
            epoch: pool.epoch ?? 0, persons: persons, ubiPerPerson: ubiPerPerson,
            ubiTotal: ubiTotal, vrpTotal: vrpTotal, foundationTotal: foundationTotal,
            titheUsed: titheUsed, minted: minted, controls: controls,
            newSupply: state.supply + minted)
    }

    /// Variable rewards split by ACTIVITY weight. Returns (tag, amount) in pool insertion order.
    public static func distributeVrp(_ pool: PoLEPool, vrpTotal: Int) -> [(Data, Int)] {
        let ta = pool.totalActivity
        if ta == 0 || vrpTotal <= 0 { return [] }
        return pool.people().map { ($0.0, vrpTotal * $0.1 / ta) }
    }

    private static func pay(_ coin: Coin, account: String, amount: Int, titheBudget: Int,
                            titheAccount: String) throws -> Int {
        if amount <= 0 { return titheBudget }
        let fromTithe = min(titheBudget, amount)
        if fromTithe != 0 { try coin.transfer(titheAccount, account, fromTithe) }
        if amount - fromTithe != 0 { try coin.mint(account, amount - fromTithe) }
        return titheBudget - fromTithe
    }

    /// Credit an issuance result to the ledger: UBI first (tithe then mint), then VRP by activity,
    /// then the Foundation pool. The tithe account must already hold `result.titheUsed`. New supply
    /// grows by exactly `result.minted`.
    public static func applyIssuance(_ coin: Coin, result: IssuanceResult, pool: PoLEPool,
                                     titheAccount: String = "tithe") throws {
        var budget = result.titheUsed
        for (pt, _) in pool.people() {                 // UBI: uniform, paid first
            budget = try pay(coin, account: Coins.accountFor(pt), amount: result.ubiPerPerson,
                             titheBudget: budget, titheAccount: titheAccount)
        }
        let shares = distributeVrp(pool, vrpTotal: result.vrpTotal)
        for (pt, amt) in shares {                       // VRP: by activity weight
            budget = try pay(coin, account: Coins.accountFor(pt), amount: amt,
                             titheBudget: budget, titheAccount: titheAccount)
        }
        let dust = result.vrpTotal - shares.reduce(0) { $0 + $1.1 }
        _ = try pay(coin, account: Coins.foundation, amount: result.foundationTotal + dust,
                    titheBudget: budget, titheAccount: titheAccount)
    }

    /// One epoch spec for `simulate`.
    public struct EpochSpec {
        public var epoch: Int
        public var persons: Int
        public var col: Int
        public var value: Int
        public var activity: Int
        public var tithe: Int
        public init(epoch: Int, persons: Int, col: Int, value: Int, activity: Int = 1, tithe: Int = 0) {
            self.epoch = epoch; self.persons = persons; self.col = col; self.value = value
            self.activity = activity; self.tithe = tithe
        }
    }

    /// Run a sequence of epochs for stress-testing (supply carries forward).
    public static func simulate(_ epochs: [EpochSpec],
                                params: PolicyParams = PolicyParams()) throws -> [IssuanceResult] {
        var state = EconomyState()
        var out: [IssuanceResult] = []
        for e in epochs {
            let pool = PoLEPool()
            for i in 0..<e.persons {
                try pool.add(try collectPoLE(personTag: Data("p\(i)".utf8), epoch: e.epoch,
                                             entropyCommit: Data("env".utf8), live: true,
                                             activityWeight: e.activity))
            }
            let r = try issue(pool, colIndex: e.col, valueIndex: e.value, titheInflow: e.tithe,
                              state: state, params: params)
            state = EconomyState(supply: r.newSupply)
            out.append(r)
        }
        return out
    }
}
