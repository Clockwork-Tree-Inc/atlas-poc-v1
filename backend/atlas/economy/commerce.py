"""Commerce over Atlas PoLE coin — the marketplace as a storefront continuous with the real store.

Businesses list (see `marketplace.Listing`, priced in APLC), accept the coin, and pay a per-sale
fee + listing fee. Those fees ARE the tithe: they route to the Foundation `tithe` account, which
closes the loop into the issuance engine (`economy.policy` draws that balance as `tithe_inflow`)
so real commerce funds UBI and backs the currency. Surfacing stays pull-based and eligibility-
gated (`marketplace.surface`): fees buy ACCESS, never RANK.

Payments here are on-ledger APLC transfers (buyer → seller), not the air-gapped offline model in
`atlas.payment` — so they don't practice the offline double-spend patterns (R7/R11) either.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Set, Tuple

from .coin import Coin, LedgerError

DEFAULT_FEE_BP = 300          # 3% per-sale tithe
TITHE_ACCOUNT = "tithe"       # the Foundation pool the issuance engine draws from


@dataclass(frozen=True)
class Sale:
    buyer: str
    seller: str
    item: bytes
    amount: int
    fee: int          # routed to the Foundation tithe pool
    epoch: int


@dataclass(frozen=True)
class Booking:
    buyer: str
    provider: str
    service: bytes
    slot: str
    amount: int
    fee: int
    epoch: int


def _fee(amount: int, fee_bp: int) -> int:
    return amount * fee_bp // 10_000


def purchase(coin: Coin, *, buyer: str, seller: str, item: bytes, amount: int, epoch: int,
             fee_bp: int = DEFAULT_FEE_BP, tithe_account: str = TITHE_ACCOUNT) -> Sale:
    """Buyer pays `amount` in APLC: the per-sale fee goes to the tithe pool, the rest to the seller.
    No new supply — pure transfer of earned coin."""
    if amount <= 0:
        raise ValueError("amount must be positive")
    if coin.balance(buyer) < amount:
        raise LedgerError("insufficient balance")
    fee = _fee(amount, fee_bp)
    coin.transfer(buyer, tithe_account, fee)          # tithe first (funds UBI next epoch)
    coin.transfer(buyer, seller, amount - fee)
    return Sale(buyer, seller, item, amount, fee, epoch)


def pay_listing_fee(coin: Coin, *, business: str, amount: int,
                    tithe_account: str = TITHE_ACCOUNT) -> int:
    """A periodic listing/membership fee — access to being surfaced (never rank). Also tithe."""
    if amount <= 0:
        raise ValueError("amount must be positive")
    coin.transfer(business, tithe_account, amount)
    return amount


class BookingBook:
    """Slot reservations for services (a barber, a clinic). One (provider, service, slot) can be
    booked once; booking pays in APLC with the same per-sale tithe as a purchase."""

    def __init__(self) -> None:
        self._taken: Set[Tuple[str, bytes, str]] = set()

    def is_free(self, provider: str, service: bytes, slot: str) -> bool:
        return (provider, service, slot) not in self._taken

    def book(self, coin: Coin, *, buyer: str, provider: str, service: bytes, slot: str,
             amount: int, epoch: int, fee_bp: int = DEFAULT_FEE_BP,
             tithe_account: str = TITHE_ACCOUNT) -> Booking:
        if amount <= 0:
            raise ValueError("amount must be positive")
        key = (provider, service, slot)
        if key in self._taken:
            raise ValueError("slot already booked")
        if coin.balance(buyer) < amount:
            raise LedgerError("insufficient balance")
        fee = _fee(amount, fee_bp)
        coin.transfer(buyer, tithe_account, fee)
        coin.transfer(buyer, provider, amount - fee)
        self._taken.add(key)
        return Booking(buyer, provider, service, slot, amount, fee, epoch)
