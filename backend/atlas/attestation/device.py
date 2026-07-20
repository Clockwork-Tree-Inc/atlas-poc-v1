"""The device-attestation contract (TRUST_LAYER.md #11) — capabilities from proof, tier from
capabilities, fail-closed.

Trust is EARNED BY DEMONSTRATION, never asserted. A device does not claim to be trusted; it
PROVES capabilities live, and the proven set determines its assurance tier. This is the
generalization of the iOS `Wearable` seam (which is just the BLE *driver*) to a device-agnostic
contract that any platform mirrors byte-for-byte.

CAPABILITIES (what a device can prove) — the bit values are part of the contract (parity):
  LIVENESS        a live presence signal (pulse/PPG) — the one universal capability
  ON_BODY_MOTION  low-rate motion — worn-vs-not / removal
  HIGH_RATE_IMU   ~50 Hz+ IMU — same-hand tap bind + ballistocardiogram
  SECURE_ELEMENT  a hardware key store — device-bound secrets / resumption codes
  SAME_BODY       cross-device coherence proving two sensors are on ONE body right now
  IDENTITY        a bound identity (enclave biometric / System-ID)

ASSURANCE TIERS compose fail-closed and MONOTONICALLY (each builds on the one below, so a
missing lower requirement caps the tier — e.g. a secure element with NO liveness is NOT
"attested", it is NONE):
  NONE        nothing proven
  PRESENCE    LIVENESS
  BOUND       PRESENCE + a body-binding proof (HIGH_RATE_IMU or SAME_BODY)
  ATTESTED    BOUND + SECURE_ELEMENT
  IDENTIFIED  ATTESTED + IDENTITY
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, IntFlag
from typing import Iterable, List

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ..crypto.primitives import H, random_bytes

_DIGEST = b"atlas/device-attestation"
_CLAIM = b"atlas/device-attest-claim"


class AttestationError(Exception):
    """A verifier-side attestation failure — an untrusted attestor key, or a stale/unknown/reused
    challenge. Fail-closed: raises rather than returning a partial result."""


class Capability(IntFlag):
    LIVENESS = 1 << 0
    ON_BODY_MOTION = 1 << 1
    HIGH_RATE_IMU = 1 << 2
    SECURE_ELEMENT = 1 << 3
    SAME_BODY = 1 << 4
    IDENTITY = 1 << 5


class AssuranceTier(IntEnum):
    NONE = 0
    PRESENCE = 1
    BOUND = 2
    ATTESTED = 3
    IDENTIFIED = 4


# Fail-closed, monotonic predicates — each builds on the one below.
def _presence(c: Capability) -> bool:
    return Capability.LIVENESS in c


def _bound(c: Capability) -> bool:
    # presence bound to one body: a same-hand tap bind (high-rate IMU) OR cross-device coherence.
    return _presence(c) and (Capability.HIGH_RATE_IMU in c or Capability.SAME_BODY in c)


def _attested(c: Capability) -> bool:
    return _bound(c) and Capability.SECURE_ELEMENT in c


def _identified(c: Capability) -> bool:
    return _attested(c) and Capability.IDENTITY in c


_LADDER = [
    (AssuranceTier.PRESENCE, _presence),
    (AssuranceTier.BOUND, _bound),
    (AssuranceTier.ATTESTED, _attested),
    (AssuranceTier.IDENTIFIED, _identified),
]


def assurance_tier(capabilities: Capability) -> AssuranceTier:
    """The highest tier whose requirements the proven capabilities meet. Fail-closed: because
    the predicates are monotonic, an out-of-order capability (e.g. SECURE_ELEMENT without
    LIVENESS) never lifts the tier."""
    tier = AssuranceTier.NONE
    for candidate, ok in _LADDER:
        if ok(capabilities):
            tier = candidate
    return tier


@dataclass(frozen=True)
class CapabilityClaim:
    """A device's claim to a capability, backed by EVIDENCE — an attestation SIGNATURE over
    (device_id, capability, challenge). A claim is admitted ONLY if that signature verifies against
    the attestor's key, so an arbitrary non-empty blob no longer forges a capability. (Real device
    attestation — App Attest / Play Integrity / Secure-Enclave — is a different verifier that
    produces this signed statement; the point here is that verification actually runs and fails
    closed on a bad or absent signature.)"""

    capability: Capability
    evidence: bytes


def _lp(b: bytes) -> bytes:
    """Length-prefix framing so a variable-length field cannot be re-split into the next one."""
    return len(b).to_bytes(4, "big") + b


def claim_message(device_id: bytes, capability: Capability, challenge: bytes) -> bytes:
    """The exact bytes an attestor signs to vouch for a capability, bound to this device + a fresh
    challenge (anti-replay). `device_id` and `challenge` are LENGTH-PREFIXED so the boundaries
    between them and the fixed-width capability are unambiguous — without this, a byte can migrate
    between the variable-length `device_id` and the capability field, colliding two distinct
    (device, capability, challenge) tuples onto one signature."""
    return H(_CLAIM, _lp(device_id), int(capability).to_bytes(4, "big"), _lp(challenge))


def sign_capability(attestor_sk: Ed25519PrivateKey, device_id: bytes,
                    capability: Capability, challenge: bytes) -> bytes:
    """Produce the evidence for a capability (the honest attestor / test side)."""
    return attestor_sk.sign(claim_message(device_id, capability, challenge))


def _verify_claim(attestor_public: bytes, device_id: bytes, capability: Capability,
                  challenge: bytes, signature: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(attestor_public).verify(
            signature, claim_message(device_id, capability, challenge))
        return True
    except Exception:
        return False


def derive_capabilities(claims: Iterable[CapabilityClaim], *, attestor_public: bytes,
                        device_id: bytes, challenge: bytes) -> Capability:
    """The proven capability set: the union of capabilities whose attestation SIGNATURE verifies.
    Fail-closed — an absent, malformed, or forged signature admits nothing."""
    proven = Capability(0)
    for claim in claims:
        if claim.evidence and _verify_claim(attestor_public, device_id, claim.capability,
                                            challenge, claim.evidence):
            proven |= claim.capability
    return proven


def attestation_digest(device_id: bytes, capabilities: Capability, tier: AssuranceTier) -> bytes:
    """A byte-exact commitment to a device's attested state — so an attestation can be logged,
    compared, or anchored identically across platforms."""
    return H(_DIGEST, device_id,
             int(capabilities).to_bytes(4, "big"), int(tier).to_bytes(1, "big"))


@dataclass(frozen=True)
class Attestation:
    """A device's attested state: who it is + what it PROVED. The tier and digest are derived,
    never set."""

    device_id: bytes
    capabilities: Capability

    @staticmethod
    def from_claims(device_id: bytes, claims: Iterable[CapabilityClaim], *,
                    attestor_public: bytes, challenge: bytes) -> "Attestation":
        """Build an attestation from claims whose signatures verify against `attestor_public` for
        this `device_id` + `challenge`. Forged/unsigned claims contribute nothing (fails closed)."""
        return Attestation(device_id=device_id, capabilities=derive_capabilities(
            claims, attestor_public=attestor_public, device_id=device_id, challenge=challenge))

    @property
    def tier(self) -> AssuranceTier:
        return assurance_tier(self.capabilities)

    def meets(self, required: AssuranceTier) -> bool:
        """Fail-closed tier gate: does this device reach at least `required`?"""
        return self.tier >= required

    def digest(self) -> bytes:
        return attestation_digest(self.device_id, self.capabilities, self.tier)

    def summary(self) -> List[str]:
        """Honest human summary of what the device can prove (order = strongest first)."""
        names = [
            (Capability.LIVENESS, "live presence"),
            (Capability.SAME_BODY, "same-body coherence"),
            (Capability.HIGH_RATE_IMU, "same-hand tap bind"),
            (Capability.ON_BODY_MOTION, "on-body motion"),
            (Capability.SECURE_ELEMENT, "secure element"),
            (Capability.IDENTITY, "bound identity"),
        ]
        return [label for cap, label in names if cap in self.capabilities]


class AttestationVerifier:
    """The STATEFUL verifier a deployment runs (C3(b) fix). The bare `derive_capabilities` /
    `from_claims` primitives trust whatever attestor key the caller passes and whatever challenge
    it is handed — so an attacker can present their OWN key and self-certify, or replay a captured
    attestation. This verifier closes both by holding state:

      * TRUST ANCHOR — a PINNED set of attestor public keys. A claim only counts if it verifies
        under one of these; a caller can no longer inject an arbitrary key. (Provision/rotate the
        set out of band; modelled here as an in-memory set.)
      * SINGLE-USE CHALLENGES — the verifier draws each challenge itself and remembers it. A
        challenge is accepted exactly once (consumed on use); an unknown or reused challenge is
        rejected, so a captured attestation cannot be replayed.

    In-memory here (a real deployment persists both the anchor and the outstanding-challenge log),
    the same modelling posture as the Secure Enclave / HSM."""

    def __init__(self, trusted_attestors: Iterable[bytes]) -> None:
        self._trusted = {bytes(a) for a in trusted_attestors}
        if not self._trusted:
            raise AttestationError("verifier requires at least one pinned attestor key")
        self._outstanding: set[bytes] = set()

    def issue_challenge(self) -> bytes:
        """Mint a fresh single-use challenge and record that we issued it (freshness comes from
        the verifier, never the prover)."""
        challenge = random_bytes(32)
        self._outstanding.add(challenge)
        return challenge

    def verify(self, device_id: bytes, claims: Iterable[CapabilityClaim],
               challenge: bytes) -> Attestation:
        """Verify claims for `device_id` answering `challenge`. Fail-closed: the challenge must be
        one we issued and not yet used (consumed here), and each capability must verify under a
        PINNED attestor key. Capabilities proven by any trusted attestor compose into the tier."""
        if challenge not in self._outstanding:
            raise AttestationError("unknown or already-used challenge (stale/replayed/forged)")
        self._outstanding.discard(challenge)             # single use — consume it
        proven = Capability(0)
        claims = list(claims)
        for attestor in self._trusted:
            proven |= derive_capabilities(claims, attestor_public=attestor,
                                          device_id=device_id, challenge=challenge)
        return Attestation(device_id=device_id, capabilities=proven)
