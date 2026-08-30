"""Redemption gate: closed-loop today, openable later by swapping the gate implementation."""
import pytest

from atlas.economy import (
    ClosedLoop,
    ClosedLoopError,
    Coin,
    FiatRedemption,
    FiatReserve,
    deposit_fiat,
)


def test_closed_loop_refuses_cash_out():
    coin, reserve = Coin(), FiatReserve()
    deposit_fiat(coin, reserve, buyer="p:a", fiat_amount=100, currency="USD", aplc_per_fiat=10)
    gate = ClosedLoop()
    with pytest.raises(ClosedLoopError):
        gate.redeem(coin, reserve, holder="p:a", aplc_amount=500, currency="USD")


def test_future_fiat_redemption_is_a_gated_stub():
    gate = FiatRedemption()
    with pytest.raises(NotImplementedError):
        gate.redeem(Coin(), FiatReserve(), holder="p:a", aplc_amount=1, currency="USD")


def test_gate_is_swappable_same_interface():
    # Opening the off-ramp later is a module swap behind the same call, not a rearchitecture.
    for gate in (ClosedLoop(), FiatRedemption()):
        assert hasattr(gate, "redeem")
