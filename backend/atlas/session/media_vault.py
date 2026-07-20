"""Media capture -> sealed vault ingestion — the capture->seal->vault reference.

The reference-of-record for the on-device capture pipeline. A photo, video, or
audio clip captured through the attested flow is, in ONE presence-gated step:

  1. PROVENANCE-SIGNED at capture (`sign_capture`) — bound to a verified-live
     author, the current LK + live session, the epoch, PAD-checked;
  2. SEALED into the presence-gated `SecureVault` (the storage key lives sealed in
     the Enclave and is released only on live presence);
  3. retrievable ONLY through a live session, whereupon its FULL provenance is
     re-verified and anything not accountable is refused (fail-closed).

Plaintext never lands outside the seal: "take a photo, it goes straight into the
Atlas folder" — where the folder is the sealed vault. This is exactly what the
Swift `AVAudioRecorder` / `AVCapture` controllers mirror on device: capture bytes
-> sign_capture -> vault.put, gated as a unit.

AUDIO AND PAD (honest boundary): PAD's depth-plane + moiré checks are CAMERA
anti-spoofing. Audio has no LiDAR depth, so for audio PAD is recorded honestly as
NOT-APPLICABLE (no depth samples) and stays purely ADVISORY — it never gates. The
*accountable* verdict for audio rests on the author signature, the live liveness
attestation (the same ambient/live-presence gate the mic capture runs under), the
live-LK/session binding, integrity, and the ledger anchor — all of which apply to
audio exactly as they do to a photo.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional, Sequence, Tuple

from ..beacon.base import BeaconRound
from ..keys.identity import Child
from ..liveness.attestation import AttestationSubsystem
from ..liveness.bayes import PoLEState
from ..provenance.capture import (
    CaptureMetadata,
    ProvenanceBundle,
    ProvenanceVerdict,
    sign_capture,
    verify_provenance,
)
from ..provenance.ledger import LedgerStub
from ..provenance.live_binding import PublicWitnessRegistry
from ..realid.levels import AssuranceLevel
from ..realid.verification import VerificationCredential
from .secure_vault import SecureVault


class MediaKind(Enum):
    """A captured medium. `motion` is the capture-metadata motion label; audio
    alone carries no camera PAD signal."""

    PHOTO = ("photo", "still")
    VIDEO = ("video", "video")
    AUDIO = ("audio", "audio")

    def __init__(self, label: str, motion: str):
        self._label = label
        self.motion = motion

    @property
    def label(self) -> str:
        return self._label

    @property
    def has_camera_pad(self) -> bool:
        """Photo/video read a LiDAR depth plane; audio does not."""
        return self is not MediaKind.AUDIO


class ProvenanceRefused(Exception):
    """Open refused: the stored media's provenance is not accountable (fail-closed)."""


@dataclass
class MediaRecord:
    """What the vault keeps per captured item beyond the sealed bytes: the full
    provenance bundle (re-verified on every open) and its ledger anchor index."""

    kind: MediaKind
    name: str
    bundle: ProvenanceBundle
    anchor_index: int


class MediaVault:
    """Capture->seal->vault ingestion over a presence-gated `SecureVault`.

    Owns the ledger the content hashes are anchored into and the public witness
    registry the live-provenance binding verifies against, so an item is
    self-verifying on open (no external anchor needed for the PoC). The LK holder
    (this device) publishes only the epoch witness PUBLIC half — the LK never
    leaves.
    """

    def __init__(self, *, vault: SecureVault, authorship: Child,
                 attestation_subsystem: Optional[AttestationSubsystem] = None):
        self._vault = vault
        self._author = authorship
        self._attest = attestation_subsystem or AttestationSubsystem()
        self._ledger = LedgerStub()
        self._registry = PublicWitnessRegistry()
        self._records: Dict[str, MediaRecord] = {}

    @property
    def witness_registry(self) -> PublicWitnessRegistry:
        return self._registry

    @property
    def ledger(self) -> LedgerStub:
        return self._ledger

    def __contains__(self, name: str) -> bool:
        return name in self._records

    def capture(
        self,
        *,
        kind: MediaKind,
        name: str,
        content: bytes,
        live_biometric: bytes,
        pole: PoLEState,
        beacon_round: BeaconRound,
        lk: bytes,
        session_key: bytes,
        depth_map: Optional[Sequence[float]] = None,
        moire_score: float = 0.0,
        camera_intrinsics: str = "iPhone",
        pad_policy: str = "advisory",
        verification_credential: Optional[VerificationCredential] = None,
    ) -> MediaRecord:
        """Capture one item: provenance-sign it, publish the epoch witness public,
        and seal the bytes into the vault — all under the SAME live presence.

        Photo/video require a real `depth_map` (+ optional `moire_score`) for PAD;
        `pad_policy="reject"` additionally refuses an obvious screen-replay at
        capture. Audio takes no depth (PAD is advisory-N/A) and always stays
        advisory.
        """
        drand_round = beacon_round.drand_round()

        if kind is MediaKind.AUDIO:
            # No camera -> no LiDAR depth. PAD is not applicable and never gates.
            depth_map, moire_score, pad_policy = (), 0.0, "advisory"
            depth_summary = "n/a (audio: no LiDAR depth)"
        else:
            if depth_map is None:
                raise ValueError(f"{kind.label} capture requires a depth_map for PAD")
            depth_summary = "lidar-depth-plane"

        metadata = CaptureMetadata(
            camera_intrinsics=camera_intrinsics,
            motion=kind.motion,
            captured_at=drand_round.hex(),          # deterministic epoch stamp (no wall clock)
            depth_summary=depth_summary,
        )

        # 1. provenance: verified-live author + live LK/session binding + anchor.
        bundle = sign_capture(
            content=content, depth_map=list(depth_map), moire_score=moire_score,
            metadata=metadata, authorship=self._author,
            attestation_subsystem=self._attest, pole=pole, beacon_round=beacon_round,
            ledger=self._ledger, lk=lk, session_key=session_key,
            verification_credential=verification_credential, pad_policy=pad_policy,
        )
        # Publish only the epoch's witness PUBLIC half (derived from the LK we hold;
        # the LK stays on-device). Recipients verify without the LK.
        self._registry.publish(lk, drand_round)

        # 2. seal the media bytes into the presence-gated vault (same live presence).
        self._vault.put(name, content, live_biometric=live_biometric, pole=pole,
                        beacon_round=beacon_round)

        rec = MediaRecord(kind=kind, name=name, bundle=bundle, anchor_index=bundle.anchor_index)
        self._records[name] = rec
        return rec

    def open(
        self,
        name: str,
        *,
        live_biometric: bytes,
        pole: PoLEState,
        required_level: AssuranceLevel = AssuranceLevel.L0,
    ) -> Tuple[bytes, ProvenanceVerdict]:
        """Retrieve a captured item under live presence and re-verify its full
        provenance. Refuses (fail-closed) anything not accountable."""
        rec = self._records[name]
        # presence-gated decrypt (+ the vault's own per-content stamp check).
        content = self._vault.get(name, live_biometric=live_biometric, pole=pole)
        verdict = verify_provenance(
            rec.bundle, content=content, ledger=self._ledger,
            witness_registry=self._registry, required_level=required_level,
        )
        if not verdict.accountable:
            raise ProvenanceRefused(f"{name}: provenance not accountable: {verdict.reasons}")
        return content, verdict

    def raw_at_rest(self, name: str) -> bytes:
        """The sealed ciphertext as stored — an unreadable brick without the
        Enclave-sealed storage key."""
        return self._vault.raw_at_rest(name)
