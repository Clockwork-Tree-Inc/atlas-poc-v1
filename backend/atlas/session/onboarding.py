"""Onboarding: the single identification phase + the phase gate (§2.1).

Locked Model §2.1 — two phases, in order:

  Phase 1 — Identification. Establishes ALL of {TSK, System-ID, device
    enrollment, pseudonyms} together in ONE phase (FIX #2). Device enrollment
    binds each device's PUBLIC auth half to the BLIND System-ID, not the person,
    for challenge-response authentication (FIX #6).

  Phase 2 — Liveness / PoLE streaming. HARD-GATED behind completed identification
    (FIX #1): `begin_liveness_streaming` raises if identification is not complete,
    and devices that stream are only ever produced BY the identification phase.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

from ..crypto.primitives import random_bytes
from ..crypto.sign import HybridSigPublic, verify as hybrid_verify
from ..keys.identity import Child, IdentityTree, PseudonymTier, build_identity_tree
from .device import Device


class PhaseError(RuntimeError):
    """PoLE/liveness streaming attempted before identification completed."""


class EnrollmentAuthority:
    """Server side of device enrollment + challenge-response (§2.4 / FIX #6).

    Holds each device's PUBLIC auth half (from enrollment), bound to the BLIND
    System-ID (never the person). Issues fresh challenges and verifies responses;
    never sees a private half. The System-ID binding is the firewall: the device
    is authenticated to a verified identity while unlinked to the human."""

    def __init__(self) -> None:
        self._enrolled: Dict[str, Tuple[HybridSigPublic, bytes]] = {}

    def enroll(self, device_name: str, public: HybridSigPublic, system_id_handle: bytes) -> None:
        self._enrolled[device_name] = (public, system_id_handle)

    def is_enrolled(self, device_name: str) -> bool:
        return device_name in self._enrolled

    def system_id_of(self, device_name: str) -> bytes:
        return self._enrolled[device_name][1]

    def issue_challenge(self) -> bytes:
        """A fresh, unpredictable challenge for challenge-response."""
        return random_bytes(32)

    def verify_response(self, device_name: str, challenge: bytes, response: bytes) -> bool:
        """Verify the device signed our challenge with the enrolled public half."""
        if device_name not in self._enrolled:
            return False
        public, _ = self._enrolled[device_name]
        return hybrid_verify(public, challenge, response)


@dataclass
class IdentifiedUser:
    tree: IdentityTree
    authority: EnrollmentAuthority
    devices: List[Device]
    pseudonyms: Dict[str, Child]
    _liveness_started: Set[str] = field(default_factory=set)


class Onboarding:
    """The identification -> liveness phase machine with a hard gate."""

    def __init__(self) -> None:
        self._identified = False
        self.user: IdentifiedUser | None = None

    @property
    def identified(self) -> bool:
        return self._identified

    def identify(self, tsk_seed: bytes, *, device_names: List[str],
                 pseudonyms: List[Tuple[str, PseudonymTier]]) -> IdentifiedUser:
        """Phase 1 — establish TSK + System-ID + device enrollment + pseudonyms
        TOGETHER (FIX #2). Returns the identified user; only now may liveness begin."""
        tree = build_identity_tree(tsk_seed)
        authority = EnrollmentAuthority()
        devices: List[Device] = []
        for name in device_names:
            dev = Device(name, tree, bootstrap_tunnel_key=random_bytes(32))
            # device enrollment is PART of identification: bind the device's public
            # auth half to the BLIND System-ID (not the person).
            authority.enroll(name, dev.device_public(), tree.system_id_handle())
            devices.append(dev)
        pmap = {label: tree.pseudonym(label, tier) for (label, tier) in pseudonyms}
        self.user = IdentifiedUser(tree=tree, authority=authority, devices=devices, pseudonyms=pmap)
        self._identified = True
        return self.user

    def begin_liveness_streaming(self, device: Device) -> Device:
        """Phase gate (FIX #1): HARD guard. No PoLE/liveness streaming until
        identification is complete, and only for a device enrolled in it."""
        if not self._identified or self.user is None:
            raise PhaseError("identification must complete before PoLE/liveness streaming")
        if device.name not in {d.name for d in self.user.devices}:
            raise PhaseError("device was not enrolled in the identification phase")
        self.user._liveness_started.add(device.name)
        return device
