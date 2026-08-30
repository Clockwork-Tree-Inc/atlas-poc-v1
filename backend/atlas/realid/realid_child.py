"""The real-world-ID child + consented, logged surfacing (Real-ID spec §1).

One dedicated child holds real-world identity. No other child carries legal
identity — the partitioning is STRUCTURAL: the other children are not derived to
hold real-ID material and have no key path to it. The real-ID child surfaces the
legal identity ONLY on explicit, logged consent for a context that requires it
(L2); never automatically.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from ..keys.identity import Child
from .storage import OnDeviceStore


class ConsentRequired(Exception):
    """L2 surfacing requires explicit user consent (Real-ID spec §1)."""


@dataclass
class SurfaceLog:
    events: List[dict] = field(default_factory=list)

    def record(self, context: str, level: str) -> None:
        self.events.append({"context": context, "level": level, "surfaced": True})


def _child_secret(child: Child) -> bytes:
    # Per-child secret = the child's Ed25519 private bytes (deterministic from the
    # child seed). Sibling children have different secrets and NO path to this
    # one — the isolation is by construction.
    return child.keypair.ed_sk.private_bytes_raw()


class RealIDVault:
    """Binds the (test) real-ID material to the real-ID child only."""

    def __init__(self, realid_child: Child):
        if realid_child.context != "real-id":
            raise ValueError("RealIDVault must be built on the real-id child")
        self._store = OnDeviceStore(_child_secret(realid_child))
        self.log = SurfaceLog()

    def bind(self, test_id_material: bytes) -> None:
        """Associate the DUMMY real-world-ID record with this child (on-device)."""
        self._store.store(test_id_material)

    def surface_legal_identity(self, *, consent: bool, context: str) -> bytes:
        """L2 surface: reveal the (test) legal identity — only on explicit,
        logged consent."""
        if not consent:
            raise ConsentRequired("L2 surfacing requires explicit user consent")
        material = self._store.surface()
        self.log.record(context=context, level="L2")
        return material

    @property
    def raw_blob_for_isolation_test(self) -> bytes:
        """The at-rest ciphertext — exposed only so a test can prove a sibling
        child's secret cannot decrypt it."""
        return self._store._blob or b""
