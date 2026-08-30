"""Fiat on-ramp: one-way, closed-loop. Fiat comes IN and backs the coin; Atlas PoLE coin is
Atlas-world-only and has NO path out to fiat (the closed loop is structural)."""
import pytest

from atlas.economy import Coin, FiatReserve, deposit_fiat, purchase
from atlas.economy import onramp


def test_deposit_fiat_credits_coin_and_holds_reserve():
    coin, reserve = Coin(), FiatReserve()
    aplc = deposit_fiat(coin, reserve, buyer="p:alice", fiat_amount=5_00,  # $5.00 in cents
                        currency="USD", aplc_per_fiat=10)
    assert aplc == 5_000                       # 500 cents * 10 APLC/cent
    assert coin.balance("p:alice") == 5_000
    assert coin.supply == 5_000                # reserve-backed mint
    assert reserve.held("USD") == 5_00         # fiat held as backing


def test_no_off_ramp_exists_closed_loop_is_structural():
    # The compliance property is the ABSENCE of any cash-out path.
    for banned in ("withdraw_fiat", "redeem_to_fiat", "cash_out", "redeem"):
        assert not hasattr(onramp, banned)


def test_on_ramped_coin_is_spendable_inside_atlas():
    coin, reserve = Coin(), FiatReserve()
    deposit_fiat(coin, reserve, buyer="p:alice", fiat_amount=1_000, currency="USD", aplc_per_fiat=10)
    # she can spend it in the market (closed-loop use), but there is no way to turn it back to fiat
    sale = purchase(coin, buyer="p:alice", seller="p:store", item=b"tea",
                    amount=1_000, epoch=1, fee_bp=300)
    assert sale.fee == 30 and coin.balance("p:store") == 970
    assert reserve.held("USD") == 1_000        # fiat stays in the Foundation reserve regardless


def test_multi_currency_reserve_and_input_validation():
    coin, reserve = Coin(), FiatReserve()
    deposit_fiat(coin, reserve, buyer="p:a", fiat_amount=100, currency="USD", aplc_per_fiat=10)
    deposit_fiat(coin, reserve, buyer="p:a", fiat_amount=200, currency="EUR", aplc_per_fiat=10)
    assert reserve.held("USD") == 100 and reserve.held("EUR") == 200
    assert coin.balance("p:a") == 3_000
    with pytest.raises(ValueError):
        deposit_fiat(coin, reserve, buyer="p:a", fiat_amount=0, currency="USD", aplc_per_fiat=10)
    with pytest.raises(ValueError):
        deposit_fiat(coin, reserve, buyer="p:a", fiat_amount=100, currency="USD", aplc_per_fiat=0)
