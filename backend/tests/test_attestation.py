"""Tests for the device-attestation contract (TRUST_LAYER.md #11)."""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from atlas.attestation.device import (
    Attestation,
    AssuranceTier,
    AttestationError,
    AttestationVerifier,
    Capability,
    CapabilityClaim,
    assurance_tier,
    attestation_digest,
    derive_capabilities,
    sign_capability,
)

C = Capability
DEVICE = b"device-1"
CHALLENGE = b"fresh-challenge"


def _attestor():
    sk = Ed25519PrivateKey.generate()
    return sk, sk.public_key().public_bytes_raw()


def _signed(sk, *caps):
    return [CapabilityClaim(c, sign_capability(sk, DEVICE, c, CHALLENGE)) for c in caps]


def test_tier_ladder():
    assert assurance_tier(C(0)) is AssuranceTier.NONE
    assert assurance_tier(C.LIVENESS) is AssuranceTier.PRESENCE
    assert assurance_tier(C.LIVENESS | C.HIGH_RATE_IMU) is AssuranceTier.BOUND
    assert assurance_tier(C.LIVENESS | C.SAME_BODY) is AssuranceTier.BOUND     # OR-binding
    assert assurance_tier(C.LIVENESS | C.SAME_BODY | C.SECURE_ELEMENT) is AssuranceTier.ATTESTED
    assert assurance_tier(C.LIVENESS | C.HIGH_RATE_IMU | C.SECURE_ELEMENT | C.IDENTITY) \
        is AssuranceTier.IDENTIFIED


def test_fail_closed_out_of_order_capabilities_do_not_lift_tier():
    # a secure element + identity but NO liveness -> NONE (not attested/identified).
    assert assurance_tier(C.SECURE_ELEMENT | C.IDENTITY) is AssuranceTier.NONE
    # liveness + secure element but NO body-binding -> only PRESENCE (bound is skipped).
    assert assurance_tier(C.LIVENESS | C.SECURE_ELEMENT) is AssuranceTier.PRESENCE
    # identity without the secure-element rung -> caps at BOUND.
    assert assurance_tier(C.LIVENESS | C.HIGH_RATE_IMU | C.IDENTITY) is AssuranceTier.BOUND


def test_on_body_motion_alone_is_not_a_body_binding():
    # on-body motion is worn-vs-not, NOT the same-body binding that lifts to BOUND.
    assert assurance_tier(C.LIVENESS | C.ON_BODY_MOTION) is AssuranceTier.PRESENCE


def test_capabilities_are_proven_by_signature_not_asserted():
    sk, pub = _attestor()
    claims = _signed(sk, C.LIVENESS, C.HIGH_RATE_IMU) + [
        CapabilityClaim(C.SECURE_ELEMENT, evidence=b""),                  # no signature -> dropped
        CapabilityClaim(C.IDENTITY, evidence=b"junk-not-a-signature"),    # forged -> dropped
    ]
    proven = derive_capabilities(claims, attestor_public=pub, device_id=DEVICE, challenge=CHALLENGE)
    assert C.LIVENESS in proven and C.HIGH_RATE_IMU in proven
    assert C.SECURE_ELEMENT not in proven and C.IDENTITY not in proven
    assert assurance_tier(proven) is AssuranceTier.BOUND


def test_forged_evidence_fails_closed():
    # THE fix: arbitrary non-empty bytes no longer forge a capability to IDENTIFIED.
    sk, pub = _attestor()
    forged = [CapabilityClaim(c, b"x") for c in
              (C.LIVENESS, C.HIGH_RATE_IMU, C.SECURE_ELEMENT, C.IDENTITY)]
    a = Attestation.from_claims(DEVICE, forged, attestor_public=pub, challenge=CHALLENGE)
    assert a.tier is AssuranceTier.NONE           # was IDENTIFIED before verification was enforced


def test_wrong_challenge_or_device_rejected():
    sk, pub = _attestor()
    claims = _signed(sk, C.LIVENESS)
    # a signature bound to CHALLENGE does not verify under a different challenge (anti-replay)
    proven = derive_capabilities(claims, attestor_public=pub, device_id=DEVICE, challenge=b"other")
    assert proven == C(0)
    # nor under a different device id
    proven2 = derive_capabilities(claims, attestor_public=pub, device_id=b"other-dev", challenge=CHALLENGE)
    assert proven2 == C(0)


def test_wrong_attestor_key_rejected():
    sk, _ = _attestor()
    _, other_pub = _attestor()
    claims = _signed(sk, C.LIVENESS, C.SAME_BODY, C.SECURE_ELEMENT)
    proven = derive_capabilities(claims, attestor_public=other_pub, device_id=DEVICE, challenge=CHALLENGE)
    assert proven == C(0)


def test_attestation_from_claims_and_meets():
    sk, pub = _attestor()
    a = Attestation.from_claims(DEVICE, _signed(sk, C.LIVENESS, C.SAME_BODY, C.SECURE_ELEMENT),
                                attestor_public=pub, challenge=CHALLENGE)
    assert a.tier is AssuranceTier.ATTESTED
    assert a.meets(AssuranceTier.PRESENCE) and a.meets(AssuranceTier.ATTESTED)
    assert not a.meets(AssuranceTier.IDENTIFIED)                # fail-closed gate


def test_digest_is_deterministic_and_sensitive():
    caps = C.LIVENESS | C.HIGH_RATE_IMU
    d1 = attestation_digest(b"dev", caps, assurance_tier(caps))
    d2 = attestation_digest(b"dev", caps, assurance_tier(caps))
    assert d1 == d2
    # any change in device / caps / tier changes the digest
    assert d1 != attestation_digest(b"dev2", caps, assurance_tier(caps))
    assert d1 != attestation_digest(b"dev", caps | C.SECURE_ELEMENT,
                                    assurance_tier(caps | C.SECURE_ELEMENT))


def test_summary_lists_only_proven_capabilities():
    a = Attestation(b"d", C.LIVENESS | C.SECURE_ELEMENT)
    s = a.summary()
    assert "live presence" in s and "secure element" in s
    assert "bound identity" not in s


def test_capability_bit_values_are_the_contract():
    # these bit values are parity-critical (Swift OptionSet raw values must match).
    assert (int(C.LIVENESS), int(C.ON_BODY_MOTION), int(C.HIGH_RATE_IMU),
            int(C.SECURE_ELEMENT), int(C.SAME_BODY), int(C.IDENTITY)) == (1, 2, 4, 8, 16, 32)


def test_claim_message_framing_is_unambiguous():
    # C3: device_id and challenge are length-prefixed, so a byte cannot migrate between the
    # variable-length device_id and the capability/challenge fields — distinct (device, cap,
    # challenge) tuples can no longer collide onto one signed message.
    from atlas.attestation.device import claim_message
    assert claim_message(b"ab", C.LIVENESS, b"c") != claim_message(b"a", C.LIVENESS, b"bc")
    assert claim_message(b"dev", C.LIVENESS, b"") != claim_message(b"de", C.LIVENESS, b"v")


def test_verifier_pins_the_attestor_key():
    # C3(b): the stateful verifier PINS the trusted attestor. An attacker who signs every
    # capability with their OWN key cannot self-certify — only claims under the pinned key count.
    real_sk, real_pub = _attestor()
    attacker_sk, _ = _attestor()
    verifier = AttestationVerifier(trusted_attestors=[real_pub])

    challenge = verifier.issue_challenge()
    forged = [CapabilityClaim(c, sign_capability(attacker_sk, DEVICE, c, challenge))
              for c in (C.LIVENESS, C.HIGH_RATE_IMU, C.SECURE_ELEMENT, C.IDENTITY)]
    att = verifier.verify(DEVICE, forged, challenge)
    assert att.tier is AssuranceTier.NONE                      # attacker key admits nothing

    challenge2 = verifier.issue_challenge()
    genuine = [CapabilityClaim(c, sign_capability(real_sk, DEVICE, c, challenge2))
               for c in (C.LIVENESS, C.HIGH_RATE_IMU, C.SECURE_ELEMENT)]
    assert verifier.verify(DEVICE, genuine, challenge2).tier is AssuranceTier.ATTESTED


def test_verifier_challenge_is_single_use():
    # C3(b): a challenge is accepted exactly once; replaying it (or using one never issued) fails.
    sk, pub = _attestor()
    verifier = AttestationVerifier(trusted_attestors=[pub])
    challenge = verifier.issue_challenge()
    claims = [CapabilityClaim(C.LIVENESS, sign_capability(sk, DEVICE, C.LIVENESS, challenge))]

    assert verifier.verify(DEVICE, claims, challenge).tier is AssuranceTier.PRESENCE  # first use ok
    with pytest.raises(AttestationError):
        verifier.verify(DEVICE, claims, challenge)             # replay -> rejected (consumed)
    with pytest.raises(AttestationError):
        verifier.verify(DEVICE, claims, b"never-issued")       # unknown challenge -> rejected


def test_verifier_requires_a_pinned_key():
    with pytest.raises(AttestationError):
        AttestationVerifier(trusted_attestors=[])
