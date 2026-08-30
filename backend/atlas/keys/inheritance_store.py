"""Persisted, beacon-verified inheritance-gated custody for the node (#3/#44).

Wraps `GatedCustody` with (a) DISK PERSISTENCE — so a node restart cannot reset a fired trigger or
a recorded veto (an attacker rebooting the custodian must not reopen the challenge), and (b) genuine
BEACON VERIFICATION — a veto's freshness proof is bound to a drand round's signature, so before the
gate accepts a veto the node checks that `beacon_sig` really is drand's signature for `at_round`
(otherwise "proof of life" could be fabricated). The clock is EXTERNAL DRAND — the party-neutral,
court-verifiable public timeline appropriate for a contested legal gate (drand in its anchor role,
NOT the epoch key). The current round for release checks is read from the node's drand beacon.

The node (`net.node_server`) exposes four calls over HTTP: arm / trigger / veto / serve. This module
is that logic, testable with injected round/verify hooks; the HTTP handlers just parse and call in.
Reference of record.
"""
from __future__ import annotations

import base64
import json
import os
from typing import Callable

from ..crypto.sign import HybridSigPublic
from . import inheritance as inh
from .inheritance_custody import GatedCustody, NotReleasable

__all__ = ["InheritanceStore", "NotReleasable", "BeaconUnverified"]


class BeaconUnverified(Exception):
    """A veto's beacon signature is not drand's genuine signature for the claimed round — rejected
    fail-closed, so freshness cannot be forged."""


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _ub64(s: str) -> bytes:
    return base64.b64decode(s)


def _safe(locator: str) -> str:
    loc = locator.strip().lower()
    if not loc or len(loc) > 128 or any(c not in "0123456789abcdef" for c in loc):
        raise ValueError("locator must be lowercase hex")
    return loc


class InheritanceStore:
    """Per-locator inheritance-gated custody, persisted as one JSON file each.

    `current_round()` returns the node's latest verified drand round number; `verify_round(round,
    sig)` returns True iff `sig` is drand's genuine BLS signature for `round` (inject the real
    `beacon.drand.verify_drand_signature(..., pubkey)` in production, a stub in tests)."""

    def __init__(self, storage_dir: str, *, current_round: Callable[[], int],
                 verify_round: Callable[[int, bytes], bool]) -> None:
        os.makedirs(storage_dir, exist_ok=True)
        self._dir = storage_dir
        self._now = current_round
        self._verify_round = verify_round

    def _path(self, locator: str) -> str:
        return os.path.join(self._dir, f"{_safe(locator)}.gate")

    def _load(self, locator: str) -> GatedCustody:
        path = self._path(locator)
        if not os.path.exists(path):
            raise KeyError(f"no gated custody at {locator}")
        with open(path) as fh:
            d = json.load(fh)
        policy = inh.InheritancePolicy(
            gate_id=bytes.fromhex(d["gate_id"]),
            owner_pub=HybridSigPublic.decode(_ub64(d["owner_pub"])),
            trigger_pub=HybridSigPublic.decode(_ub64(d["trigger_pub"])),
            veto_window_rounds=d["veto_window_rounds"],
        )
        state = inh.GateState(triggered_at=d["triggered_at"], veto_count=d["veto_count"],
                              released=d["released"])
        return GatedCustody(policy=policy, heir_blob=_ub64(d["heir_blob"]), state=state)

    def _save(self, locator: str, gc: GatedCustody) -> None:
        d = {
            "gate_id": gc.policy.gate_id.hex(),
            "owner_pub": _b64(gc.policy.owner_pub.encode()),
            "trigger_pub": _b64(gc.policy.trigger_pub.encode()),
            "veto_window_rounds": gc.policy.veto_window_rounds,
            "heir_blob": _b64(gc.heir_blob),
            "triggered_at": gc.state.triggered_at,
            "veto_count": gc.state.veto_count,
            "released": gc.state.released,
        }
        tmp = self._path(locator) + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(d, fh)
        os.replace(tmp, self._path(locator))   # atomic: a crash never leaves a half-written gate

    # -- the four node operations ------------------------------------------------------------
    def arm(self, *, locator: str, heir_blob: bytes, gate_id: bytes,
            owner_pub: HybridSigPublic, trigger_pub: HybridSigPublic, veto_window_rounds: int) -> None:
        """Register a heir share under a fresh inheritance gate. Refuses to clobber an existing one."""
        if os.path.exists(self._path(locator)):
            raise ValueError("a gated custody already exists at this locator")
        policy = inh.InheritancePolicy(gate_id=gate_id, owner_pub=owner_pub, trigger_pub=trigger_pub,
                                       veto_window_rounds=veto_window_rounds)
        self._save(locator, GatedCustody(policy=policy, heir_blob=heir_blob))

    def trigger(self, *, locator: str, at_round: int, signature: bytes) -> str:
        gc = self._load(locator)
        gc.trigger(at_round=at_round, signature=signature)   # fail-closed on a bad attorney sig
        self._save(locator, gc)
        return gc.status(now_round=self._now())

    def veto(self, *, locator: str, at_round: int, beacon_sig: bytes, signature: bytes) -> str:
        # Freshness: the veto is bound to a drand round's signature; verify that signature is genuine
        # BEFORE the gate accepts it, so a fabricated `beacon_sig` cannot pass off a pre-signed veto.
        if not self._verify_round(at_round, beacon_sig):
            raise BeaconUnverified(f"beacon_sig is not drand's signature for round {at_round}")
        gc = self._load(locator)
        gc.veto(at_round=at_round, beacon_sig=beacon_sig, signature=signature)
        self._save(locator, gc)
        return gc.status(now_round=self._now())

    def serve(self, *, locator: str) -> bytes:
        """Return the heir blob IFF the gate is releasable at the node's current round; else fail
        closed (`NotReleasable`)."""
        gc = self._load(locator)
        blob = gc.serve(now_round=self._now())    # raises NotReleasable unless the gate is open
        return blob

    def status(self, *, locator: str) -> str:
        return self._load(locator).status(now_round=self._now())
