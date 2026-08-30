"""Atlas PoLE coin economy: PoLE proofs, the issuance policy (UBI-first, COL-indexed, tithe-funded,
supply-controlled), and the transferable coin ledger. Foundation-run, earned-only, no company account."""
import pytest

from atlas.economy import (
    FOUNDATION,
    Coin,
    EconomyState,
    NotLiveError,
    PoLEPool,
    PolicyParams,
    account_for,
    apply_issuance,
    collect_pole,
    distribute_vrp,
    issue,
    simulate,
)

PAR = 10_000  # value_index at par


# ------------------------------- PoLE ---------------------------------------

def test_pole_requires_a_live_unique_person():
    with pytest.raises(NotLiveError):
        collect_pole(b"p1", 1, b"env", live=False)
    p = collect_pole(b"p1", 1, b"env", live=True, activity_weight=3)
    assert p.activity_weight == 3


def test_pool_dedupes_per_person_keeps_max_activity():
    pool = PoLEPool()
    pool.add(collect_pole(b"alice", 1, b"e", live=True, activity_weight=1))
    pool.add(collect_pole(b"alice", 1, b"e", live=True, activity_weight=4))  # same person, re-submit
    pool.add(collect_pole(b"bob", 1, b"e", live=True, activity_weight=2))
    assert pool.persons == 2                      # alice counted once (presence)
    assert pool.activity_of(b"alice") == 4        # kept the higher activity
    assert pool.total_activity == 6


def test_pool_rejects_mixed_epochs():
    pool = PoLEPool()
    pool.add(collect_pole(b"a", 1, b"e", live=True))
    with pytest.raises(ValueError):
        pool.add(collect_pole(b"b", 2, b"e", live=True))


# ------------------------------- issuance policy ----------------------------

def _pool(n, epoch=1, activity=1):
    pool = PoLEPool()
    for i in range(n):
        pool.add(collect_pole(f"p{i}".encode(), epoch, b"e", live=True, activity_weight=activity))
    return pool


def test_ubi_is_col_indexed_and_real_value_preserved_when_token_falls():
    st = EconomyState(supply=1_000_000)
    at_par = issue(_pool(10), col_index=100, value_index=PAR, state=st)
    devalued = issue(_pool(10), col_index=100, value_index=5_000, state=st)  # token worth half
    # coin-denominated UBI rises to hold the real floor...
    assert devalued.ubi_per_person > at_par.ubi_per_person
    # ...and the REAL floor (coin * value) is preserved at col_index
    assert at_par.ubi_per_person * PAR // PAR == 100
    assert devalued.ubi_per_person * 5_000 // PAR == 100
    assert "value_below_par" in devalued.controls


def test_low_col_gives_more_vrp_high_col_gives_more_ubi():
    st = EconomyState(supply=1_000_000)          # headroom to fund VRP
    low = issue(_pool(10), col_index=100, value_index=PAR, state=st)
    high = issue(_pool(10), col_index=6_000, value_index=PAR, state=st)
    assert low.vrp_total > high.vrp_total                 # less cost of living -> more variable reward
    assert high.ubi_total > low.ubi_total                 # more cost of living -> more UBI
    assert high.vrp_total == 0                            # UBI absorbs everything under the cap
    assert "ubi_exceeds_growth_cap" in high.controls      # floor alone forces expansion (emergency)


def test_ubi_paid_first_steady_state_split_is_70_20_10():
    st = EconomyState(supply=10_000_000)          # ample headroom
    r = issue(_pool(10), col_index=100, value_index=PAR, state=st)
    total = r.ubi_total + r.vrp_total + r.foundation_total
    # 20 / 70 / 10 of the total (within integer rounding)
    assert abs(r.ubi_total * 100 // total - 20) <= 1
    assert abs(r.vrp_total * 100 // total - 70) <= 1
    assert abs(r.foundation_total * 100 // total - 10) <= 1


def test_tithe_funds_first_and_reduces_minting():
    st = EconomyState(supply=1_000_000)
    no_tithe = issue(_pool(10), col_index=100, value_index=PAR, state=st, tithe_inflow=0)
    covered = issue(_pool(10), col_index=100, value_index=PAR, state=st, tithe_inflow=10_000)
    assert no_tithe.minted > 0
    assert covered.minted == 0                       # real revenue backed the whole epoch
    assert covered.tithe_used == covered.ubi_total + covered.vrp_total + covered.foundation_total
    assert "tithe_backed" in covered.controls


# ------------------------------- coin ledger --------------------------------

def test_coin_transfer_and_guards():
    c = Coin()
    c._mint("p:alice", 100)
    c.transfer("p:alice", "p:bob", 30)
    assert c.balance("p:alice") == 70 and c.balance("p:bob") == 30
    with pytest.raises(Exception):
        c.transfer("p:bob", "p:alice", 999)          # insufficient
    with pytest.raises(Exception):
        c.transfer("p:alice", "p:bob", 0)            # non-positive


def test_apply_issuance_credits_ubi_vrp_foundation_and_conserves_supply():
    c = Coin()
    c._mint("tithe", 10_000)                         # businesses pre-funded the tithe pool
    assert c.supply == 10_000
    st = EconomyState(supply=10_000)
    pool = PoLEPool()
    pool.add(collect_pole(b"p0", 1, b"e", live=True, activity_weight=1))
    pool.add(collect_pole(b"p1", 1, b"e", live=True, activity_weight=3))
    r = issue(pool, col_index=100, value_index=PAR, tithe_inflow=5_000, state=st)

    apply_issuance(c, r, pool)

    # supply grew by exactly what was minted; ledger conserves (sum of balances == supply)
    assert c.supply == r.new_supply
    assert sum(c.accounts().values()) == c.supply
    # UBI uniform; VRP proportional to activity (p1 has 3x); Foundation funded
    assert c.balance(account_for(b"p1")) > c.balance(account_for(b"p0"))
    assert c.balance(FOUNDATION) >= r.foundation_total
    # earned-only, Foundation-run: the only non-person accounts are the tithe pool + Foundation
    assert all(k.startswith("p:") or k in (FOUNDATION, "tithe") for k in c.accounts())
    assert not any("company" in k or "founder" in k for k in c.accounts())


def test_distribute_vrp_is_proportional_to_activity():
    pool = _pool(0)
    pool.add(collect_pole(b"a", 1, b"e", live=True, activity_weight=1))
    pool.add(collect_pole(b"b", 1, b"e", live=True, activity_weight=4))
    d = distribute_vrp(pool, 1000)
    assert d[b"b"] == 4 * d[b"a"]


# ------------------------------- stress simulation --------------------------

def test_simulation_ubi_floor_holds_and_controls_fire_under_stress():
    results = simulate([
        {"epoch": 1, "persons": 5, "col": 100, "value": PAR, "tithe": 0},      # genesis: UBI only
        {"epoch": 2, "persons": 5, "col": 100, "value": PAR, "tithe": 0},      # cap binds -> emergency
        {"epoch": 3, "persons": 5, "col": 100, "value": PAR, "tithe": 2_000},  # tithe relieves minting
    ])
    supplies = [r.new_supply for r in results]
    assert supplies == sorted(supplies)                       # supply monotonic non-decreasing
    assert "ubi_exceeds_growth_cap" in results[1].controls    # UBI floor forced expansion past the cap
    assert results[1].vrp_total == 0                          # discretionary throttled
    assert results[2].minted < results[1].minted              # tithe backing cut new minting
    # UBI floor never dropped (real value preserved every epoch)
    assert all(r.ubi_per_person * r_value // PAR == 100
               for r, r_value in zip(results, [PAR, PAR, PAR]))
