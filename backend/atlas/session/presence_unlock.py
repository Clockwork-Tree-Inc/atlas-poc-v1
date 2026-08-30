"""Unlock tiers + presence state machine — the MAX tier is held ONLY while live presence is fresh.

Two things gate what a session may do, and they compose fail-closed:

  UNLOCK TIER — how strongly the human authenticated at unlock:
    LOCKED   — nothing.
    BASIC    — Face ID / biometric (possession + a weak liveness).
    STANDARD — + passcode (carries the duress channel; a duress code unlocks to a scoped view).
    MAX       — + continuous live-presence (PoLE), i.e. a wearable-backed "a live human is here now".

  PRESENCE FRESHNESS — MAX is not a latch. It is earned tick-by-tick: each PoLE tick stamps the
    current beacon round; if no tick lands within `freshness_window_rounds`, presence goes STALE and
    the effective tier DROPS to STANDARD until presence resumes. Walk away / take the wearable off →
    high-assurance capability evaporates, without re-entering the passcode.

`effective_tier(now_round)` is the live answer: min(what you unlocked to, what presence currently
permits). A duress unlock caps the effective tier to a scoped `DURESS` level regardless of presence
(the cryptographic persona-scoping of duress is #40; here duress just caps the gate).

Beacon-clocked so freshness is measured in verifiable drand rounds, not spoofable wall-clock.
Reference of record. Swift parity: ios/AtlasCore/Sources/AtlasCore/Session/PresenceUnlock.swift.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Optional


class UnlockTier(IntEnum):
    LOCKED = 0
    DURESS = 1        # a scoped, limited view reached via the duress code (capped, never MAX)
    BASIC = 2         # Face ID / biometric
    STANDARD = 3      # + passcode
    MAX = 4           # + continuous live presence (PoLE)


@dataclass(frozen=True)
class PresencePolicy:
    freshness_window_rounds: int      # a PoLE tick keeps presence live for this many beacon rounds

    def __post_init__(self):
        if self.freshness_window_rounds <= 0:
            raise ValueError("freshness_window_rounds must be > 0")


@dataclass
class UnlockState:
    unlocked_tier: UnlockTier = UnlockTier.LOCKED   # the ceiling reached by the unlock event
    last_presence_round: Optional[int] = None       # beacon round of the most recent PoLE tick
    duress: bool = False


def on_unlock(state: UnlockState, tier: UnlockTier, *, duress: bool = False) -> UnlockState:
    """Record an unlock. A duress unlock is capped at DURESS regardless of the tier attempted."""
    if duress:
        state.duress = True
        state.unlocked_tier = UnlockTier.DURESS
    else:
        state.duress = False
        state.unlocked_tier = tier
    return state


def on_presence_tick(state: UnlockState, *, now_round: int) -> UnlockState:
    """A fresh PoLE tick landed at `now_round`. Only advances the clock (never regresses it)."""
    if state.last_presence_round is None or now_round > state.last_presence_round:
        state.last_presence_round = now_round
    return state


def on_lock(state: UnlockState) -> UnlockState:
    state.unlocked_tier = UnlockTier.LOCKED
    state.last_presence_round = None
    state.duress = False
    return state


def presence_live(state: UnlockState, policy: PresencePolicy, *, now_round: int) -> bool:
    """Presence is live iff a PoLE tick landed within the freshness window ending at now_round."""
    r = state.last_presence_round
    return r is not None and 0 <= (now_round - r) <= policy.freshness_window_rounds


def effective_tier(state: UnlockState, policy: PresencePolicy, *, now_round: int) -> UnlockTier:
    """The tier actually in force right now: the unlock ceiling, lowered if presence isn't live.
    MAX requires fresh presence; without it the session falls back to STANDARD. Duress caps at
    DURESS. Fail-closed everywhere."""
    if state.duress:
        return UnlockTier.DURESS
    if state.unlocked_tier < UnlockTier.MAX:
        return state.unlocked_tier
    # unlocked to MAX — only keep it while presence is live, else drop to STANDARD
    return UnlockTier.MAX if presence_live(state, policy, now_round=now_round) else UnlockTier.STANDARD


def allows(state: UnlockState, policy: PresencePolicy, *, now_round: int, required: UnlockTier) -> bool:
    """Does the session currently meet `required`? A duress session never satisfies BASIC+ actions
    (it only satisfies DURESS-level, i.e. the scoped view)."""
    return effective_tier(state, policy, now_round=now_round) >= required
