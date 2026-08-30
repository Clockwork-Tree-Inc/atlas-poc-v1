"""Commerce over Atlas PoLE coin: pay-in-coin purchases + bookings, per-sale fees routed to the
Foundation tithe pool, and the closed loop — commerce fees fund the next epoch's UBI."""
import pytest

from atlas.economy import (
    BookingBook,
    Coin,
    EconomyState,
    LedgerError,
    PoLEPool,
    apply_issuance,
    collect_pole,
    issue,
    pay_listing_fee,
    purchase,
)

PAR = 10_000
TITHE = "tithe"


def _funded(buyer: str, amount: int) -> Coin:
    c = Coin()
    c._mint(buyer, amount)   # simulate the buyer having earned coin
    return c


def test_purchase_pays_seller_and_routes_fee_to_tithe():
    c = _funded("p:buyer", 1_000)
    sale = purchase(c, buyer="p:buyer", seller="p:store", item=b"kombucha",
                    amount=1_000, epoch=1, fee_bp=300)  # 3%
    assert sale.fee == 30
    assert c.balance("p:store") == 970       # seller gets amount - fee
    assert c.balance(TITHE) == 30            # fee -> Foundation tithe pool
    assert c.balance("p:buyer") == 0
    assert c.supply == 1_000                 # pure transfer, no new supply


def test_purchase_rejects_insufficient_balance():
    c = _funded("p:buyer", 10)
    with pytest.raises(LedgerError):
        purchase(c, buyer="p:buyer", seller="p:store", item=b"x", amount=100, epoch=1)


def test_listing_fee_is_tithe():
    c = _funded("p:store", 500)
    pay_listing_fee(c, business="p:store", amount=200)
    assert c.balance(TITHE) == 200 and c.balance("p:store") == 300


def test_booking_reserves_slot_and_double_book_rejected():
    c = _funded("p:buyer", 1_000)
    book = BookingBook()
    b = book.book(c, buyer="p:buyer", provider="p:barber", service=b"haircut",
                  slot="2026-08-12T10:00", amount=400, epoch=1, fee_bp=300)
    assert b.fee == 12 and c.balance("p:barber") == 388 and c.balance(TITHE) == 12
    assert not book.is_free("p:barber", b"haircut", "2026-08-12T10:00")
    with pytest.raises(ValueError):
        book.book(c, buyer="p:buyer", provider="p:barber", service=b"haircut",
                  slot="2026-08-12T10:00", amount=400, epoch=1)   # same slot


def test_closed_loop_commerce_fees_fund_next_epoch_ubi():
    # Businesses transact; per-sale fees accrue in the tithe pool...
    c = Coin()
    c._mint("p:shopper", 100_000)            # shopper earned coin
    for i in range(5):
        purchase(c, buyer="p:shopper", seller=f"p:store{i}", item=b"item",
                 amount=10_000, epoch=1, fee_bp=300)  # 5 x 300 = 1500 in tithe
    assert c.balance(TITHE) == 1_500

    # ...and the issuance engine draws that tithe to fund UBI, minting less (or nothing).
    st = EconomyState(supply=c.supply)
    pool = PoLEPool()
    for i in range(10):
        pool.add(collect_pole(f"p{i}".encode(), 2, b"env", live=True))
    r = issue(pool, col_index=100, value_index=PAR, tithe_inflow=c.balance(TITHE), state=st)

    assert "tithe_backed" in r.controls
    assert r.tithe_used > 0                   # real commerce revenue funded distributions
    # UBI (10 persons x 100) fully covered by tithe -> zero minting for the floor
    assert r.ubi_total == 1_000 and r.tithe_used >= r.ubi_total
    apply_issuance(c, r, pool)
    assert sum(c.accounts().values()) == c.supply   # ledger conserved end-to-end
