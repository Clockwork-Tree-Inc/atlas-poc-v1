"""Presence interop — the "consumable verified-human" object. ONE Proof-of-Living-Entropy presence
attestation, emitted in EVERY standard format a consumer already speaks:

  * as_vc   → a W3C Verifiable Credential (JWS) — for scoped-fact / selective-disclosure flows;
  * as_oidc → an OpenID Connect ID Token — for "Sign in with Atlas";
  * as_c2pa_payload → the inputs c2pa.embed_assertion embeds — so a content asset proves it was made
    by a verified live human, at tier T, at round R.

Same claim in all three ("a live human, at drand round R, at assurance tier T, bound to this exact
presentation"), each verifiable OFFLINE by signature — no phone-home, and personas don't correlate
across apps. This is the adoption wedge: an app consumes Atlas through WebAuthn / OIDC / VC / C2PA
without a relationship with us and without us learning it happened.

Composes primitives that already exist (attestation.presence_attestation, interop.assertion / vc /
oidc / c2pa). No new crypto. Reference of record.
"""
from __future__ import annotations

import time
from typing import Any, Dict

from ..attestation.presence_attestation import PresenceAttestation
from ..crypto.sign import HybridSigKeypair
from . import oidc, vc
from .assertion import AtlasAssertion, kid_of

CLAIM_LIVE_HUMAN = "atlas.verified-live-human"


def _epoch_hex(att: PresenceAttestation) -> str:
    return format(att.beacon_round, "x")


def presence_assertion(kp: HybridSigKeypair, att: PresenceAttestation, *, subject: str,
                       now: float | None = None) -> AtlasAssertion:
    """The canonical Atlas assertion for a presence attestation — verdicts only, no secrets. The
    assurance tier is stated INSIDE (honest + falsifiable); the verifier decides whether it suffices."""
    return AtlasAssertion(
        subject=subject,
        claim_type=CLAIM_LIVE_HUMAN,
        claims={
            "verified_human": True,
            "assurance_tier": int(att.tier),
            "assurance_tier_name": att.tier.name,
            "presentation_binding": att.presentation_binding.hex(),
        },
        issued_at=now if now is not None else time.time(),
        epoch=_epoch_hex(att),
        issuer_kid=kid_of(kp.public),
    )


def as_vc(kp: HybridSigKeypair, att: PresenceAttestation, *, subject: str,
          now: float | None = None) -> str:
    """A W3C Verifiable Credential (compact JWS) carrying the presence claim."""
    return vc.to_jws(kp, presence_assertion(kp, att, subject=subject, now=now))


def as_oidc(kp: HybridSigKeypair, att: PresenceAttestation, *, subject: str, audience: str,
            nonce: str, ttl_s: float = 300.0, now: float | None = None) -> str:
    """An OpenID Connect ID Token asserting a verified live human at this tier — 'Sign in with Atlas'."""
    t = now if now is not None else time.time()
    return oidc.id_token(
        kp, subject=subject, audience=audience, nonce=nonce, epoch=_epoch_hex(att),
        issued_at=t, expires_at=t + ttl_s,
        extra={"assurance_tier": int(att.tier), "assurance_tier_name": att.tier.name,
               "presentation_binding": att.presentation_binding.hex()},
    )


def as_c2pa_payload(kp: HybridSigKeypair, att: PresenceAttestation, *, subject: str,
                    now: float | None = None) -> Dict[str, Any]:
    """The inputs `interop.c2pa.embed_assertion` needs to bake the SAME presence VC into a signed C2PA
    manifest (the embed itself uses the c2pa native lib). Result: a content asset that proves it was
    made by a verified live human at tier T — readable by any C2PA verifier (Adobe, CAWG tooling)."""
    return {
        "vc_jws": as_vc(kp, att, subject=subject, now=now),
        "verdict": f"verified-live-human/tier-{int(att.tier)}",
        "issuer_did": "did:atlas:" + kid_of(kp.public),
    }
