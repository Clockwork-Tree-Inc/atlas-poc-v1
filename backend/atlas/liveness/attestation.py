"""Ratchet-paced liveness attestation + removal states (§5.3, §5.4).

§5.3: a continuity-sensing subsystem inside the Secure Enclave emits a fresh
*signed* attestation each ratchet step, independent of the key path. Reward/value
eligibility is gated by this attestation or the reward layer is farmable.

§5.4 removal states (corrected §2.3 / FIX #13 — EVERY end path is inert at rest):
  * Voluntary (proper end / ritual): goes INERT — stops ratcheting AND wipes RAM
    key material, exactly like the other end paths. Differs from suspicious ONLY
    in the reconnection discriminator (a coherent re-bind is benign; no full
    recovery). (Supersedes the earlier "consume down, keep ratcheting" model.)
  * Suspicious (no ritual): immediate drop, halt of liveness-gated authority,
    stop attestations, RAM key-wipe, full recovery required; vault stays
    encrypted at rest (an unreadable brick until recovery).
  * Reconnection discriminator: audit the ring's ratchet trajectory across a
    gap — coherent => benign (light re-bind); incoherent/absent => suspicious.
  There is NO end path that leaves the device ratcheting or key material live.

At Tier 3 the phone's enclave signature stands in for the absent ring_SE_sig
(§5.2). Here that is a hybrid ML-DSA+Ed25519 signature.

Trust anchor — honest boundary (what this software models vs what is
hardware-gated):

  * What the SOFTWARE proves. `enclave_key` is an ordinary keypair generated in
    process. The attestation therefore proves only: possession of that private
    key, the PoLE digest/operate decision it signed, the epoch it is bound to,
    and — via `challenge` — that the signature is FRESH for this request. A
    relying party that pins the public key (Mode-2 binds H(enclave_public)) gets
    "the holder of THIS key is live and online right now."

  * What is HARDWARE-GATED (NOT simulated here). Nothing in this model proves the
    private key actually lives inside a genuine Secure Enclave — non-extractable,
    biometry-gated, on un-jailbroken Apple hardware — rather than having been
    generated or extracted into software. That root-of-trust requires Apple App
    Attest / DeviceCheck (a key attested back to Apple's CA) and a hardware
    tamper boundary. We deliberately do NOT fake an attestation CA: see
    HARDWARE_TESTING.md for the on-device verification of this anchor. Until that
    runs, treat the signer as "a key the app holds," not "a proven Enclave key."
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from ..crypto.sign import (
    HybridSigKeypair,
    HybridSigPublic,
    generate_sig_keypair,
    sign,
    verify,
)
from .bayes import PoLEState


class RemovalState(Enum):
    ACTIVE = "active"
    VOLUNTARY = "voluntary"      # proper end: inert at rest (wiped), benign re-bind
    SUSPICIOUS = "suspicious"    # halted + RAM wiped, full recovery required


@dataclass(frozen=True)
class LivenessAttestation:
    """Signed proof emitted each ratchet step (§5.3).

    `challenge` binds a verifier-supplied freshness nonce into the signature.
    Epoch-binding alone stops cross-epoch replay, but within one epoch a captured
    operate=True attestation could be replayed at a later view. A fresh challenge
    chosen by the relying party (see tunnel.open_message) forces the recipient's
    live Enclave to sign THIS request: a captured/static attestation carries the
    wrong (old/empty) challenge and is rejected.
    """

    drand_round: bytes
    pole_digest: bytes
    operate: bool
    enclave_public: HybridSigPublic
    signature: bytes
    challenge: bytes = b""

    def verify(self) -> bool:
        return verify(self.enclave_public, self._message(), self.signature)

    def _message(self) -> bytes:
        return self.message_for(self.drand_round, self.pole_digest, self.operate, self.challenge)

    @staticmethod
    def message_for(drand_round: bytes, pole_digest: bytes, operate: bool,
                    challenge: bytes = b"") -> bytes:
        # SECURITY: length-prefix every field (4-byte big-endian) so the signed
        # message is an INJECTIVE function of (drand_round, pole_digest, operate,
        # challenge). A plain `|`-delimited concatenation is ambiguous — a 0x7c
        # byte inside drand_round (raw beacon randomness) is an alternative split
        # point, letting one signature re-parse to a different drand_round/challenge.
        # This mirrors hkdf_combine's length-prefixing discipline (primitives.py).
        flag = b"\x01" if operate else b"\x00"
        parts = [b"atlas/attest", drand_round, pole_digest, flag, challenge]
        return b"".join(len(p).to_bytes(4, "big") + p for p in parts)


class AttestationSubsystem:
    """Models the Enclave-resident continuity sensor (§5.3). Owns the removal-state
    machine and the wipe callback that destroys RAM session keys (§5.4 / §2.2).

    `enclave_key` here is a software keypair: the subsystem proves possession +
    freshness + the signed decision, NOT a hardware-attested Enclave root (that
    is App Attest / DeviceCheck, hardware-gated — see module docstring)."""

    def __init__(self, enclave_key: Optional[HybridSigKeypair] = None):
        self.enclave_key = enclave_key or generate_sig_keypair()
        self.state = RemovalState.ACTIVE
        self._on_wipe = None

    def on_wipe(self, callback) -> None:
        """Register the RAM key-wipe (the containment hook, §2.2)."""
        self._on_wipe = callback

    @property
    def contributes_presence(self) -> bool:
        return self.state == RemovalState.ACTIVE

    @property
    def ratchets(self) -> bool:
        # Corrected model (§2.3 / FIX #13): EVERY end path is inert at rest. Only
        # ACTIVE ratchets — voluntary/proper-end and suspicious both stop.
        return self.state == RemovalState.ACTIVE

    def attest(self, pole: PoLEState, *, challenge: bytes = b"") -> Optional[LivenessAttestation]:
        """Emit a signed attestation for this ratchet step, if still attesting.

        Suspicious state stops attestations (§5.4). A non-operating PoLE
        (P(L|S) < pi*) is a liveness break -> trigger suspicious removal.

        `challenge` is a fresh verifier nonce signed into the attestation so a
        relying party can demand proof of liveness *now* (anti-replay, §9.2).
        """
        if self.state == RemovalState.SUSPICIOUS:
            return None
        if not pole.operate:
            # Liveness break: containment fires.
            self.mark_suspicious()
            return None
        msg = LivenessAttestation.message_for(
            pole.drand_round, pole.state_digest, pole.operate, challenge)
        sig = sign(self.enclave_key, msg)
        return LivenessAttestation(
            drand_round=pole.drand_round,
            pole_digest=pole.state_digest,
            operate=pole.operate,
            enclave_public=self.enclave_key.public,
            signature=sig,
            challenge=challenge,
        )

    # -- removal transitions (§5.4) -----------------------------------------

    def remove_voluntary(self) -> None:
        """Voluntary / proper session-end: go INERT at rest (FIX #13). Like every
        other end path it stops ratcheting AND wipes RAM key material — the device
        is an unreadable brick at rest. It differs from suspicious ONLY in the
        reconnection discriminator: a coherent re-bind is benign (light re-bind),
        no full recovery required. Fail-closed, never fail-stale."""
        if self.state == RemovalState.SUSPICIOUS:
            return
        self.state = RemovalState.VOLUNTARY
        if self._on_wipe is not None:
            self._on_wipe()

    def mark_suspicious(self) -> None:
        """Suspicious: halt authority, stop attestations, wipe RAM keys."""
        self.state = RemovalState.SUSPICIOUS
        if self._on_wipe is not None:
            self._on_wipe()

    def reconnect(self, *, trajectory_coherent: bool) -> RemovalState:
        """Reconnection discriminator (§5.4): coherent => benign light re-bind;
        incoherent/absent => suspicious => wipe + full recovery."""
        if trajectory_coherent:
            if self.state == RemovalState.VOLUNTARY:
                self.state = RemovalState.ACTIVE  # light re-bind
            return self.state
        self.mark_suspicious()
        return self.state
