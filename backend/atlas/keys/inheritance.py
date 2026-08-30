"""Inheritance gate — release an heir's custody share ONLY on a death-trigger AND only if the owner
fails to veto by proving they're alive.

The problem with handing a lawyer a plain recovery share: a threshold of your custodians could
reconstruct you *while you are alive*. This gate closes that. It is a beacon-clocked state machine —
clocked on EXTERNAL DRAND, deliberately: a death-trigger and challenge window is a court-contestable
legal event, so its clock must be the PARTY-NEUTRAL, third-party/court-verifiable public timeline.
That is drand in its anchor role — NOT drand as the epoch key (the epoch key is the aggregator's QRNG
`beacon.epoch`, an internal single-party beacon, unsuitable as the sole arbiter of a contested
inheritance). The gate enforces:

    release  ==  a death-trigger fired   AND   the owner did not prove liveness within the window

  * TRIGGER — the executor/lawyer signs a death-trigger at some drand round. That opens a CHALLENGE
    window of `veto_window_rounds`.
  * VETO (liveness) — within the window the OWNER signs a liveness proof bound to a *post-trigger*
    drand round's signature (unforgeable freshness: they could not have pre-signed it — the round had
    not been published yet). A valid veto ABORTS this trigger — the owner is demonstrably alive — and
    they are alerted someone tried.
  * RELEASE — only if the window elapses with no veto does the heir's share become releasable.

This is the gate LOGIC (pure, deterministic, testable). The node layer composes it with
`server_custody`: a custodian only serves the sealed heir share once the gate reads `releasable`,
and the drand round + BLS signature it is fed are verified authentic at the node (`beacon.drand`).

Reference of record. Swift parity: ios/AtlasCore/Sources/AtlasCore/Keys/Inheritance.swift.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..crypto.primitives import H
from ..crypto.sign import HybridSigPublic, verify

_TRIGGER = b"atlas/inherit/trigger/v1"
_VETO = b"atlas/inherit/veto/v1"


class InheritanceError(Exception):
    """Base — every failure is fail-closed (raises); the gate never releases on ambiguity."""


class NotTriggered(InheritanceError):
    """A veto/release was attempted with no active death-trigger."""


class WindowElapsed(InheritanceError):
    """A veto arrived before the trigger or after the challenge window closed."""


class BadAuthority(InheritanceError):
    """A trigger or veto signature did not verify against the designated key."""


def _be8(n: int) -> bytes:
    return int(n).to_bytes(8, "big")


def trigger_message(gate_id: bytes, at_round: int) -> bytes:
    return H(_TRIGGER, gate_id, _be8(at_round))


def veto_message(gate_id: bytes, at_round: int, beacon_sig: bytes) -> bytes:
    # Binds the owner's liveness proof to a specific post-trigger drand round's BLS SIGNATURE —
    # unpredictable until that round is published, so a veto cannot be pre-signed ahead of the
    # trigger. drand (party-neutral, court-verifiable) is the right freshness source for this legal
    # gate; its (round, signature) shape is exactly what the node verifies.
    return H(_VETO, gate_id, _be8(at_round), beacon_sig)


@dataclass(frozen=True)
class InheritancePolicy:
    # Inheritance is a LEGAL process: the attorney/representative triggers, the OWNER vetoes by
    # proving liveness, a time-lock gives the challenge window, and the appointed heir's share
    # releases if unchallenged. Guardians are NOT involved here (they are for the LIVING owner's
    # own recovery); disputes defer to a COURT, supported by this beacon-clocked, tamper-evident
    # record and the time-lock — the system provides the window and the evidence, not the verdict.
    gate_id: bytes                 # binds all signatures to THIS gate (no cross-gate replay)
    owner_pub: HybridSigPublic     # who can VETO (prove alive)
    trigger_pub: HybridSigPublic   # who can TRIGGER (attorney / representative / executor)
    veto_window_rounds: int        # challenge window length, in drand rounds (the time-lock)

    def __post_init__(self):
        if self.veto_window_rounds <= 0:
            raise ValueError("veto_window_rounds must be > 0")
        if len(self.gate_id) < 16:
            raise ValueError("gate_id must be >= 16 bytes")


@dataclass
class GateState:
    triggered_at: Optional[int] = None   # drand round the active trigger fired (None = armed)
    veto_count: int = 0                  # how many times the owner has vetoed (for alerting)
    released: bool = False


def apply_trigger(policy: InheritancePolicy, state: GateState, *, at_round: int, signature: bytes) -> GateState:
    """The attorney/representative fires a death-trigger at `at_round`, (re)opening the challenge
    window. Fail-closed on a bad signature; a no-op if already released."""
    if state.released:
        raise InheritanceError("gate already released")
    if not verify(policy.trigger_pub, trigger_message(policy.gate_id, at_round), signature):
        raise BadAuthority("trigger signature invalid")
    state.triggered_at = at_round
    return state


def apply_veto(policy: InheritancePolicy, state: GateState, *, at_round: int,
               beacon_sig: bytes, signature: bytes) -> GateState:
    """Owner proves liveness within the window -> ABORT this trigger. The proof must be at a round
    at/after the trigger and within the window, and signed over a post-trigger beacon signature."""
    if state.triggered_at is None:
        raise NotTriggered("no active death-trigger to veto")
    if at_round < state.triggered_at:
        raise WindowElapsed("veto predates the trigger")
    if at_round > state.triggered_at + policy.veto_window_rounds:
        raise WindowElapsed("veto arrived after the challenge window closed")
    if not verify(policy.owner_pub, veto_message(policy.gate_id, at_round, beacon_sig), signature):
        raise BadAuthority("veto (liveness) signature invalid")
    state.triggered_at = None          # the owner is alive -> abort; a later trigger can re-open
    state.veto_count += 1
    return state


def can_release(policy: InheritancePolicy, state: GateState, *, now_round: int) -> bool:
    """Release is permitted iff a trigger is active, the window has fully elapsed, and there was no
    veto (a veto clears `triggered_at`, so a vetoed gate can never satisfy this)."""
    return (not state.released
            and state.triggered_at is not None
            and now_round > state.triggered_at + policy.veto_window_rounds)


def mark_released(policy: InheritancePolicy, state: GateState, *, now_round: int) -> GateState:
    if not can_release(policy, state, now_round=now_round):
        raise InheritanceError("release conditions not met (need trigger + elapsed window + no veto)")
    state.released = True
    return state


def status(policy: InheritancePolicy, state: GateState, *, now_round: int) -> str:
    """Human-facing state: 'released' | 'releasable' | 'challenge' | 'armed'."""
    if state.released:
        return "released"
    if state.triggered_at is None:
        return "armed"
    if now_round > state.triggered_at + policy.veto_window_rounds:
        return "releasable"
    return "challenge"
