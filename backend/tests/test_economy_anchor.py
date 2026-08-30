"""Public economics anchored to the accountability log as ROOTS — supply/issuance, business-books
head, governance — while individual balances stay private (never anchored here)."""
from atlas.economy import (
    Coin,
    EconomyState,
    PoLEPool,
    TransparencyLedger,
    business_sale,
    collect_pole,
    issue,
)
from atlas.economy.anchor import (
    ECONOMY_GOVERNANCE,
    ECONOMY_SUPPLY,
    ECONOMY_TRANSPARENCY,
    anchor_governance,
    anchor_issuance,
    anchor_transparency,
    governance_root,
    issuance_root,
)
from atlas.ledger.backend import LocalBackend


def _r(n: int) -> bytes:
    return n.to_bytes(8, "big")


def _issue():
    pool = PoLEPool()
    for i in range(10):
        pool.add(collect_pole(f"p{i}".encode(), 1, b"e", live=True))
    return issue(pool, col_index=100, value_index=10_000, state=EconomyState(supply=1_000_000))


def test_issuance_anchored_as_a_root_not_content():
    b = LocalBackend()
    r = _issue()
    anchor_issuance(b, r, epoch_round=_r(1))
    root = b.latest(ECONOMY_SUPPLY)
    assert root == issuance_root(r)                       # deterministic public commitment
    assert len(root) == 32                               # a hash — not raw amounts/balances
    assert str(r.new_supply).encode() not in root        # facts are committed, not exposed


def test_transparency_head_anchored():
    coin = Coin()
    coin._mint("p:shopper", 10_000)
    led = TransparencyLedger()
    led.register_business("biz:a", identified=True)
    business_sale(coin, led, seller="biz:a", buyer="p:shopper", item=b"x", amount=1_000, epoch=1)
    b = LocalBackend()
    anchor_transparency(b, led, epoch_round=_r(1))
    assert b.latest(ECONOMY_TRANSPARENCY) == led.head()  # the books are checkpointed by their head


def test_governance_anchored():
    b = LocalBackend()
    anchor_governance(b, epoch=7, col_index=120, value_index=8_000, epoch_round=_r(1))
    assert b.latest(ECONOMY_GOVERNANCE) == governance_root(7, 120, 8_000)


def test_public_streams_are_separate():
    b = LocalBackend()
    anchor_issuance(b, _issue(), epoch_round=_r(1))
    anchor_governance(b, epoch=1, col_index=100, value_index=10_000, epoch_round=_r(2))
    assert b.latest(ECONOMY_SUPPLY) is not None
    assert b.latest(ECONOMY_GOVERNANCE) is not None
    assert b.latest(ECONOMY_SUPPLY) != b.latest(ECONOMY_GOVERNANCE)
