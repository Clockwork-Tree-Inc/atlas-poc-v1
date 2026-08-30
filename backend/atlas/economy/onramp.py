"""Fiat on-ramp — ONE-WAY, closed-loop.

Users bring REAL money IN and receive Atlas PoLE coin to spend inside Atlas. The coin is
**Atlas-world-only**: it is earned, transferred, and spent inside the ecosystem, but it **never
cashes out to fiat** — there is deliberately no reverse function anywhere. That makes APLC
*closed-loop stored value* (the gift-card / in-ecosystem-currency model), not an open-loop
transmittable asset and not an investment vehicle.

The fiat received is held by the FOUNDATION as a RESERVE that (a) backs the coin's internal
purchasing power — a real, exogenous backing alongside the business tithe (the anti-Terra
reserve) — and (b) can help fund UBI and running costs. It is safeguarded, never company profit.

Coin minted here is fully reserve-backed and is a DISTINCT path from `policy` issuance (which is
entropy/tithe-driven for UBI + rewards); the buyer earns their coin by paying fiat, so no company
account is ever the mint target.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict

from .coin import Coin


@dataclass
class FiatReserve:
    """Foundation-held fiat received via the on-ramp, in minor units (e.g. cents), per currency."""
    _held: Dict[str, int] = field(default_factory=dict)

    def held(self, currency: str) -> int:
        return self._held.get(currency, 0)

    def _add(self, currency: str, amount: int) -> None:
        self._held[currency] = self.held(currency) + amount


def deposit_fiat(coin: Coin, reserve: FiatReserve, *, buyer: str, fiat_amount: int,
                 currency: str, aplc_per_fiat: int) -> int:
    """Bring fiat IN → receive Atlas PoLE coin to spend inside Atlas. Fiat goes to the Foundation
    reserve (backing); the APLC minted is fully reserve-backed. Returns the APLC credited.

    There is intentionally NO reverse — see the module note. The closed loop is STRUCTURAL: the
    absence of a redeem/withdraw path is the compliance property, not a runtime check."""
    if fiat_amount <= 0:
        raise ValueError("fiat_amount must be positive")
    if aplc_per_fiat <= 0:
        raise ValueError("aplc_per_fiat (the governed rate) must be positive")
    aplc = fiat_amount * aplc_per_fiat
    reserve._add(currency, fiat_amount)   # fiat held as backing
    coin._mint(buyer, aplc)               # reserve-backed mint to the buyer (never a company account)
    return aplc


# NOTE: there is deliberately no `withdraw_fiat` / `redeem_to_fiat` / `cash_out`. Atlas PoLE coin
# is Atlas-world-only. Do not add one without counsel — it would convert a closed-loop stored-value
# system into open-loop money transmission.
