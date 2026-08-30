"""Inheritance-gated custody (#44/#3) — a custodian serves the sealed HEIR share ONLY once the
inheritance gate reads 'releasable': the attorney/representative fired a death-trigger, the time-lock
(challenge window) has fully elapsed, and the owner did not veto by proving liveness.

Composes `keys.inheritance` (the pure, tested gate) with a held opaque blob. This is the LOGIC the
node exposes over its custody endpoints — the custodian holds the heir blob but cannot hand it over
until the gate opens, so "a lawyer holds it, released only after death and a challenge period" is
enforced cryptographically, not by trust. The gate is clocked on external DRAND — the party-neutral,
court-verifiable public timeline appropriate for a contested legal event (drand in its anchor role,
NOT as the epoch key). The drand rounds and trigger/veto signatures the node feeds in are
beacon-verified at the node boundary (`net.node_server`).

Inheritance is a LEGAL process — attorney triggers, owner vetoes, time-lock, court-contestable — with
NO guardians involved (guardians are for the living owner's own recovery). Reference of record.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import inheritance as inh


class NotReleasable(Exception):
    """The gate is not releasable yet (armed / in the challenge window / vetoed) — fail-closed."""


@dataclass
class GatedCustody:
    """One heir share held under an inheritance gate. `heir_blob` is opaque to the custodian; it is
    returned by `serve` only while the gate is releasable, so the custodian can hold it indefinitely
    without ever being able to release it early."""

    policy: inh.InheritancePolicy
    heir_blob: bytes
    state: inh.GateState = field(default_factory=inh.GateState)

    def trigger(self, *, at_round: int, signature: bytes) -> None:
        """The attorney/representative fires the death-trigger, opening the challenge window."""
        inh.apply_trigger(self.policy, self.state, at_round=at_round, signature=signature)

    def veto(self, *, at_round: int, beacon_sig: bytes, signature: bytes) -> None:
        """The owner proves liveness within the window, aborting the trigger."""
        inh.apply_veto(self.policy, self.state, at_round=at_round, beacon_sig=beacon_sig,
                       signature=signature)

    def status(self, *, now_round: int) -> str:
        """'armed' | 'challenge' | 'releasable' | 'released'."""
        return inh.status(self.policy, self.state, now_round=now_round)

    def serve(self, *, now_round: int) -> bytes:
        """Return the heir blob IFF the gate is releasable; otherwise fail closed. Idempotent — the
        heir may fetch more than once while releasable (no partial-transfer footgun); finalize with
        `mark_released` when the handover is confirmed."""
        if not inh.can_release(self.policy, self.state, now_round=now_round):
            raise NotReleasable(f"gate is '{self.status(now_round=now_round)}', not releasable")
        return self.heir_blob

    def mark_released(self, *, now_round: int) -> None:
        """Record the one-shot handover (defence in depth: after this, `serve` fails closed)."""
        inh.mark_released(self.policy, self.state, now_round=now_round)
