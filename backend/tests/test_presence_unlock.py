"""Unlock tiers + presence state machine (#42): MAX is held only while live presence is fresh."""
import pytest

from atlas.session.presence_unlock import (PresencePolicy, UnlockState, UnlockTier, allows,
                                           effective_tier, on_lock, on_presence_tick, on_unlock,
                                           presence_live)

POL = PresencePolicy(freshness_window_rounds=5)


def test_below_max_presence_is_irrelevant():
    st = on_unlock(UnlockState(), UnlockTier.STANDARD)
    assert effective_tier(st, POL, now_round=1000) == UnlockTier.STANDARD   # no presence needed
    assert allows(st, POL, now_round=1000, required=UnlockTier.STANDARD)
    assert not allows(st, POL, now_round=1000, required=UnlockTier.MAX)


def test_max_requires_fresh_presence_and_decays_to_standard():
    st = on_unlock(UnlockState(), UnlockTier.MAX)
    on_presence_tick(st, now_round=100)
    assert presence_live(st, POL, now_round=103)
    assert effective_tier(st, POL, now_round=103) == UnlockTier.MAX          # within window
    assert allows(st, POL, now_round=103, required=UnlockTier.MAX)
    # no tick for > window rounds -> presence stale -> MAX drops to STANDARD
    assert not presence_live(st, POL, now_round=106)                         # 106 - 100 > 5
    assert effective_tier(st, POL, now_round=106) == UnlockTier.STANDARD
    assert not allows(st, POL, now_round=106, required=UnlockTier.MAX)
    assert allows(st, POL, now_round=106, required=UnlockTier.STANDARD)      # keeps standard


def test_presence_tick_restores_max():
    st = on_unlock(UnlockState(), UnlockTier.MAX)
    on_presence_tick(st, now_round=100)
    assert effective_tier(st, POL, now_round=110) == UnlockTier.STANDARD     # decayed
    on_presence_tick(st, now_round=110)                                      # live human returns
    assert effective_tier(st, POL, now_round=112) == UnlockTier.MAX


def test_presence_tick_never_regresses_the_clock():
    st = UnlockState()
    on_presence_tick(st, now_round=100)
    on_presence_tick(st, now_round=90)                                       # stale/replayed tick
    assert st.last_presence_round == 100


def test_duress_unlock_caps_at_duress_and_denies_normal_actions():
    st = on_unlock(UnlockState(), UnlockTier.MAX, duress=True)               # tier attempted ignored
    on_presence_tick(st, now_round=100)                                      # even with live presence
    assert effective_tier(st, POL, now_round=100) == UnlockTier.DURESS
    assert allows(st, POL, now_round=100, required=UnlockTier.DURESS)        # scoped view only
    assert not allows(st, POL, now_round=100, required=UnlockTier.BASIC)     # no normal capability
    assert not allows(st, POL, now_round=100, required=UnlockTier.MAX)


def test_lock_resets_everything():
    st = on_unlock(UnlockState(), UnlockTier.MAX)
    on_presence_tick(st, now_round=100)
    on_lock(st)
    assert effective_tier(st, POL, now_round=101) == UnlockTier.LOCKED
    assert not allows(st, POL, now_round=101, required=UnlockTier.BASIC)


def test_window_must_be_positive():
    with pytest.raises(ValueError):
        PresencePolicy(freshness_window_rounds=0)
