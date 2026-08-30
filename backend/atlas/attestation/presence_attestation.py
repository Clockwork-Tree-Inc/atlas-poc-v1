"""Presence attestation — a signed, verifiable statement that a PLAUSIBLE LIVE HUMAN was present at
a beacon round, at an assurance tier, BOUND to a specific credential presentation.

What it claims, and what it never claims:
  * It asserts "a live human was present," NOT who. Presence is never identified from behaviour —
    identity is the SEPARATE crypto: the persona key that signs this attestation. This keeps
    unlinkability intact (a verifier learns "a live human presented this", not a behavioural
    fingerprint).
  * FRESHNESS is the drand round's signature — unpredictable until that round is published, so an
    attestation cannot be pre-made ("not before" round R).
  * BINDING is the hash of the exact credential-presentation transcript, so an attestation cannot be
    lifted and replayed onto a DIFFERENT presentation.

Assurance tiers (honest + falsifiable): AMBIENT (phone sensors TIME/GATE the engine — NOT a
biological proof) < WEARABLE (a certified on-body secure-element device — continuous biological
presence). The tier is stated INSIDE the attestation; the verifier decides whether it suffices.

Binding to credential presentation: when a persona presents a credential (the WebAuthn atlas
extension, or a verifiable credential), it MAY attach a presence attestation over the SAME
transcript. The verifier then learns "this credential was presented by a live human, present at
round R, at tier T" — presence bound to the presentation, not merely to possession of a key.

Verification is by the persona's public key + the drand round (its authenticity checked against the
League-of-Entropy group key elsewhere). Reference of record.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from ..crypto.primitives import H
from ..crypto.sign import HybridSigKeypair, HybridSigPublic, sign, verify

_LABEL = b"atlas/presence-attestation/v1"


class AssuranceTier(IntEnum):
    AMBIENT = 1     # phone sensors — times/gates the engine; not a biological presence proof
    WEARABLE = 2    # certified on-body secure-element device — continuous biological presence


def _msg(*, beacon_round: int, beacon_sig: bytes, tier: AssuranceTier, presentation_binding: bytes) -> bytes:
    return H(_LABEL, int(beacon_round).to_bytes(8, "big"), beacon_sig,
             bytes([int(tier)]), presentation_binding)


@dataclass(frozen=True)
class PresenceAttestation:
    beacon_round: int            # the drand round the presence held at ("not before" this round)
    tier: AssuranceTier
    presentation_binding: bytes  # H(the credential-presentation transcript this is bound to)
    signature: bytes             # persona key over _msg(...) — this is the ONLY identity link


def attest(signer: HybridSigKeypair, *, beacon_round: int, beacon_sig: bytes,
           tier: AssuranceTier, presentation_binding: bytes) -> PresenceAttestation:
    """The persona signs a presence claim bound to (this drand round's signature) AND (this exact
    presentation). `beacon_sig` is the round's drand signature — signing over it is what makes the
    attestation un-pre-makeable."""
    sig = sign(signer, _msg(beacon_round=beacon_round, beacon_sig=beacon_sig,
                            tier=tier, presentation_binding=presentation_binding))
    return PresenceAttestation(beacon_round, tier, presentation_binding, sig)


def verify_attestation(pub: HybridSigPublic, att: PresenceAttestation, *, beacon_sig: bytes,
                       presentation_binding: bytes, min_tier: AssuranceTier) -> bool:
    """Accept iff: the attestation is bound to THIS presentation, its tier meets `min_tier`, and the
    signature verifies over the drand round signature the verifier independently fetched. Fail-closed.
    (The verifier separately checks `beacon_sig` is an authentic drand round — see beacon.drand.)"""
    if att.presentation_binding != presentation_binding:
        return False
    if att.tier < min_tier:
        return False
    return verify(pub, _msg(beacon_round=att.beacon_round, beacon_sig=beacon_sig,
                            tier=att.tier, presentation_binding=presentation_binding), att.signature)
