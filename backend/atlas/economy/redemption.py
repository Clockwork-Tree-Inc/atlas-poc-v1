"""Redemption gate — the (currently CLOSED) fiat off-ramp seam.

Atlas PoLE coin is Atlas-world-only TODAY (see `onramp`: fiat in, no cash-out). The design
anticipates OPENING a fiat off-ramp LATER — but only once:
  1. money-transmitter / e-money licensing + KYC/AML are in place (the "legal work"),
  2. the coin has organic utility value and is sufficiently decentralised (the securities-safe
     moment — no single promoter drives price), and
  3. the reserve is adequate to honour redemptions (you cannot open a cash-out you can't back).
Opening is then a MODULE SWAP behind this gate — `ClosedLoop` → `FiatRedemption` — not a
rearchitecture. Enabling it is precisely what turns Atlas into a money transmitter, so it stays
gated behind counsel + governance.
"""
from __future__ import annotations

from typing import Protocol

from .coin import Coin
from .onramp import FiatReserve


class ClosedLoopError(Exception):
    """Raised on any attempt to cash out while the off-ramp is closed (the default)."""


class RedemptionGate(Protocol):
    def redeem(self, coin: Coin, reserve: FiatReserve, *, holder: str,
               aplc_amount: int, currency: str) -> int: ...


class ClosedLoop:
    """DEFAULT — no off-ramp. Atlas PoLE coin never leaves the Atlas world."""

    def redeem(self, coin: Coin, reserve: FiatReserve, *, holder: str,
               aplc_amount: int, currency: str) -> int:
        raise ClosedLoopError("Atlas-world-only: the fiat off-ramp is not open")


class FiatRedemption:
    """STUB for the future open state. Do NOT implement without counsel: a real version must gate
    on licensing + KYC/AML on the holder, verify reserve adequacy before paying out, and be enabled
    by governance. Its mere existence is money transmission — that is why it is a stub, not a TODO."""

    def redeem(self, coin: Coin, reserve: FiatReserve, *, holder: str,
               aplc_amount: int, currency: str) -> int:  # pragma: no cover
        raise NotImplementedError(
            "fiat off-ramp not open — requires licensing, KYC/AML, reserve adequacy, governance"
        )
