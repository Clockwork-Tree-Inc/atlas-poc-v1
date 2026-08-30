"""The LKG aggregator + Epoch-beacon service — runs on ATLAS'S OWN SERVERS.

This is TRUSTED Atlas infrastructure, deliberately SEPARATE from the blind relay node
(`net.node_server.AtlasNode`), which any operator can run and which holds no keys and sees no
secrets. Co-locating this with the relay would be wrong: the aggregator is the single most trusted
component in the system.

Roles (all Atlas-operated):
  * It is the ONLY party that observes Living-Key ARRIVALS from the collector nodes — and only their
    arrivals, never the secret LK values (those stay sealed in SE/HSM network-wide).
  * It holds the epoch SIGNING KEY (HSM-backed in production; a persisted seed here) and runs the
    QRNG `EpochBeacon`, firing on aggregate LK-arrival timing (random cadence).
  * It PUBLISHES signed epoch rounds (the epoch key). Relays and devices only CONSUME and VERIFY
    these rounds against the pinned aggregator public key — they never run this service.

External drand is bound in per round as the OPTIONAL defence-in-depth anchor; it is not the key.
"""

from __future__ import annotations

import os
from typing import Optional

from ..crypto.primitives import random_bytes
from ..crypto.sign import HybridSigKeypair, HybridSigPublic, keypair_from_seed
from .epoch import EpochBeacon, EpochRound
from .qrng import ArrivalTiming


class EpochBeaconService:
    """The Atlas-operated aggregator. Give `storage_dir` to persist the signing seed (so the
    aggregator keeps a STABLE identity across restarts, HSM-backed in production); omit it for an
    ephemeral test instance."""

    def __init__(self, *, storage_dir: Optional[str] = None,
                 signer: Optional[HybridSigKeypair] = None) -> None:
        self._signer = signer or self._load_or_create_key(storage_dir)
        self._beacon = EpochBeacon(signer=self._signer)

    @staticmethod
    def _load_or_create_key(storage_dir: Optional[str]) -> HybridSigKeypair:
        if storage_dir is None:
            return keypair_from_seed(random_bytes(32))     # ephemeral (tests)
        os.makedirs(storage_dir, exist_ok=True)
        path = os.path.join(storage_dir, "aggregator.seed")
        if os.path.exists(path):
            with open(path, "rb") as fh:
                seed = fh.read()
        else:
            seed = random_bytes(32)
            tmp = path + ".tmp"
            with open(tmp, "wb") as fh:
                fh.write(seed)
            os.replace(tmp, path)                          # atomic: never a half-written seed
        return keypair_from_seed(seed)

    @property
    def public(self) -> HybridSigPublic:
        """The aggregator verification key — pinned by relays/devices to verify epoch rounds."""
        return self._signer.public

    def ingest_arrivals(self, arrivals: ArrivalTiming, *, anchor: bytes = b"") -> EpochRound:
        """A batch of collector-node LK arrivals reached the aggregator: fire the QRNG epoch (their
        timing TIMES the firing; the value stays clean QRNG). Production entry point."""
        return self._beacon.fire(arrivals, anchor=anchor)

    def latest(self) -> EpochRound:
        """The most recently published epoch round (what a relay serves/forwards)."""
        return self._beacon.latest()

    def current(self, *, anchor: bytes = b"") -> EpochRound:
        """PoC/self-contained driver: advance one epoch now and return it. In production the service
        fires from real `ingest_arrivals`, and a relay calls `latest()` instead. `anchor` binds an
        external-drand round for defence-in-depth."""
        now = 0.0
        return self._beacon.fire(ArrivalTiming([now, now + 0.03, now + 0.07]), anchor=anchor)
