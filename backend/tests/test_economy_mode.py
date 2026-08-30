"""Beta = receipts, not tokens. In Mode.BETA the monetary coin operations are disabled (no live
token → no securities exposure during testing); they go live only at Mode.FULL (full release).
Non-monetary receipts (soul-bound participation, transparency, the provenance trail) are unaffected."""
import pytest

from atlas.economy import (
    BetaReceiptsOnly,
    Coin,
    FiatReserve,
    LedgerError,
    Mode,
    deposit_fiat,
    purchase,
)


def test_full_mode_is_the_default_and_monetary_ops_work():
    c = Coin()                                   # default = FULL
    assert c.mode is Mode.FULL
    c._mint("p:a", 100)
    c.transfer("p:a", "p:b", 40)
    assert c.balance("p:b") == 40 and c.supply == 100


def test_beta_disables_transfer_and_mint():
    c = Coin(mode=Mode.BETA)
    with pytest.raises(BetaReceiptsOnly):
        c._mint("p:a", 100)                      # no monetary minting in beta
    with pytest.raises(BetaReceiptsOnly):
        c.transfer("p:a", "p:b", 1)              # no monetary transfer in beta


def test_beta_disables_market_and_fiat_onramp():
    # fund an account under FULL, then flip to BETA — monetary ops are then refused
    c = Coin()
    c._mint("p:a", 1_000)
    c.mode = Mode.BETA
    with pytest.raises(BetaReceiptsOnly):
        purchase(c, buyer="p:a", seller="biz:x", item=b"i", amount=100, epoch=1)  # via transfer
    with pytest.raises(BetaReceiptsOnly):
        deposit_fiat(c, FiatReserve(), buyer="p:a", fiat_amount=100, currency="USD",
                     aplc_per_fiat=10)           # via _mint


def test_beta_receipts_only_is_a_ledger_error_subclass():
    # existing `except LedgerError` handling still catches the beta refusal
    assert issubclass(BetaReceiptsOnly, LedgerError)
