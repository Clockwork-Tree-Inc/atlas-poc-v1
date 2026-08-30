"""Issuance policy — the Atlas PoLE coin monetary engine, run by the Foundation.

Per epoch, from the aggregated PoLE pool and two GOVERNED signals:
  * `col_index`   — cost-of-living level (drives UBI: higher COL → more UBI, lower → more room
                    for variable rewards). Denominated in coin at the current token value so the
                    REAL floor is preserved.
  * `value_index` — token market value in bp of par (10 000 = par). Falling value auto-raises the
                    coin-denominated UBI (to hold the real floor) and trips the controls.
Both signals are INJECTED — produced by governance (see the module note on the certified-nonprofit
vote + oracle anchor), never by the protocol.

Funding order (this is where the tithe enters): the **business tithe** (real revenue paid to the
Foundation for access) funds distributions FIRST — so it backs the currency and reduces minting —
and only the shortfall is MINTED, bounded by a supply-growth cap (the hyperinflation guard). UBI is
the sacrosanct floor: it is always fully funded (tithe then mint), even if that mint exceeds the cap
(which raises an emergency control flag). Variable rewards + the Foundation pool are the capped,
discretionary remainder.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple

from .coin import FOUNDATION, Coin, account_for
from .pole import PoLEPool, collect_pole


@dataclass(frozen=True)
class PolicyParams:
    ubi_share_bp: int = 2000       # steady-state 20 / 70 / 10
    vrp_share_bp: int = 7000
    foundation_share_bp: int = 1000
    max_supply_growth_bp: int = 500  # hyperinflation guard: <=5% NEW (minted) supply / epoch
    scale: int = 10_000              # bp baseline (10 000 = par)


@dataclass
class EconomyState:
    supply: int = 0


@dataclass(frozen=True)
class IssuanceResult:
    epoch: int
    persons: int
    ubi_per_person: int
    ubi_total: int
    vrp_total: int
    foundation_total: int
    tithe_used: int      # funded by real business revenue (no new supply)
    minted: int          # newly created supply (the shortfall after tithe)
    controls: Tuple[str, ...]
    new_supply: int

    @property
    def real_ubi(self) -> int:
        """UBI per person expressed back in real (cost-of-living) units — should track col_index,
        confirming the real floor is preserved as token value moves."""
        return self.ubi_per_person  # (caller multiplies by value_index/scale to check; see tests)


def issue(pool: PoLEPool, *, col_index: int, value_index: int, tithe_inflow: int = 0,
          state: EconomyState, params: PolicyParams = PolicyParams()) -> IssuanceResult:
    if value_index <= 0:
        raise ValueError("value_index must be positive")
    if tithe_inflow < 0:
        raise ValueError("tithe_inflow must be non-negative")

    persons = pool.persons
    ubi_per_person = col_index * params.scale // value_index   # real floor / token value
    ubi_total = ubi_per_person * persons
    non_ubi_target = ubi_total * (params.vrp_share_bp + params.foundation_share_bp) \
        // max(params.ubi_share_bp, 1)

    cap = state.supply * params.max_supply_growth_bp // params.scale   # max NEW supply (0 at genesis)

    # UBI floor is sacrosanct: fund from tithe first, mint the rest (even past the cap → flag).
    tithe_for_ubi = min(tithe_inflow, ubi_total)
    ubi_minted = ubi_total - tithe_for_ubi
    tithe_left = tithe_inflow - tithe_for_ubi

    # Discretionary (VRP + Foundation): leftover tithe first, then remaining mint headroom.
    mint_headroom = max(0, cap - ubi_minted)
    discretionary = min(non_ubi_target, tithe_left + mint_headroom)
    disc_from_tithe = min(tithe_left, discretionary)
    disc_minted = discretionary - disc_from_tithe

    denom = params.vrp_share_bp + params.foundation_share_bp
    vrp_total = discretionary * params.vrp_share_bp // denom if denom else 0
    foundation_total = discretionary - vrp_total

    minted = ubi_minted + disc_minted
    tithe_used = tithe_for_ubi + disc_from_tithe

    controls: List[str] = []
    if discretionary < non_ubi_target:
        controls.append("vrp_throttled")             # growth-cap bit (hyperinflation guard)
    if state.supply > 0 and ubi_minted > cap:
        controls.append("ubi_exceeds_growth_cap")    # emergency: floor alone forces expansion
    if value_index < params.scale:
        controls.append("value_below_par")           # devaluation: UBI coin auto-raised
    if tithe_inflow > 0:
        controls.append("tithe_backed")              # real revenue is backing this epoch

    return IssuanceResult(
        epoch=pool.epoch or 0, persons=persons, ubi_per_person=ubi_per_person,
        ubi_total=ubi_total, vrp_total=vrp_total, foundation_total=foundation_total,
        tithe_used=tithe_used, minted=minted, controls=tuple(controls),
        new_supply=state.supply + minted,
    )


def distribute_vrp(pool: PoLEPool, vrp_total: int) -> Dict[bytes, int]:
    """Variable rewards split by ACTIVITY weight (behaviour / continuous-liveness raises a share)."""
    ta = pool.total_activity
    if ta == 0 or vrp_total <= 0:
        return {}
    return {pt: vrp_total * w // ta for pt, w in pool.people().items()}


def _pay(coin: Coin, account: str, amount: int, tithe_budget: int, tithe_account: str) -> int:
    """Pay `amount` to `account`, drawing real revenue from the tithe account first (supply-neutral),
    minting only the shortfall. Returns the remaining tithe budget."""
    if amount <= 0:
        return tithe_budget
    from_tithe = min(tithe_budget, amount)
    if from_tithe:
        coin.transfer(tithe_account, account, from_tithe)
    if amount - from_tithe:
        coin._mint(account, amount - from_tithe)
    return tithe_budget - from_tithe


def apply_issuance(coin: Coin, result: IssuanceResult, pool: PoLEPool, *,
                   tithe_account: str = "tithe") -> None:
    """Credit an issuance result to the ledger: UBI first (funded by tithe, then mint), then VRP by
    activity, then the Foundation pool. The tithe account must already hold `result.tithe_used`
    (real coin businesses paid). New supply grows by exactly `result.minted`."""
    budget = result.tithe_used
    for pt in pool.people():                       # UBI: uniform, paid first
        budget = _pay(coin, account_for(pt), result.ubi_per_person, budget, tithe_account)
    shares = distribute_vrp(pool, result.vrp_total)
    for pt, amt in shares.items():                 # VRP: by activity weight
        budget = _pay(coin, account_for(pt), amt, budget, tithe_account)
    dust = result.vrp_total - sum(shares.values())
    _pay(coin, FOUNDATION, result.foundation_total + dust, budget, tithe_account)


def simulate(epochs: List[dict], params: PolicyParams = PolicyParams()) -> List[IssuanceResult]:
    """Run a sequence of epochs for stress-testing. Each dict: {epoch, persons, col, value,
    activity?, tithe?}. Returns the per-epoch results (supply carries forward)."""
    state = EconomyState()
    out: List[IssuanceResult] = []
    for e in epochs:
        pool = PoLEPool()
        for i in range(e["persons"]):
            pool.add(collect_pole(f"p{i}".encode(), e["epoch"], b"env",
                                  live=True, activity_weight=e.get("activity", 1)))
        r = issue(pool, col_index=e["col"], value_index=e["value"],
                  tithe_inflow=e.get("tithe", 0), state=state, params=params)
        state = EconomyState(supply=r.new_supply)
        out.append(r)
    return out
