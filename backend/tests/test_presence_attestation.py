"""Presence attestation (PART 6): a live-human-present claim bound to a beacon round + a specific
credential presentation, verifiable without revealing identity from behaviour."""
from atlas.attestation.presence_attestation import (AssuranceTier, attest, verify_attestation)
from atlas.crypto.primitives import H, random_bytes
from atlas.crypto.sign import generate_sig_keypair

ROUND = 4_200_000
BSIG = random_bytes(96)                     # stand-in for a drand round's BLS signature
BINDING = H(b"presentation-transcript", b"challenge-nonce", b"rp=acme")


def _att(kp, tier=AssuranceTier.WEARABLE, binding=BINDING, bsig=BSIG):
    return attest(kp, beacon_round=ROUND, beacon_sig=bsig, tier=tier, presentation_binding=binding)


def test_roundtrip_binds_presence_to_this_presentation():
    kp = generate_sig_keypair()
    att = _att(kp)
    assert verify_attestation(kp.public, att, beacon_sig=BSIG,
                              presentation_binding=BINDING, min_tier=AssuranceTier.AMBIENT)


def test_cannot_be_replayed_onto_a_different_presentation():
    kp = generate_sig_keypair()
    att = _att(kp)
    other = H(b"a-different-presentation")
    assert not verify_attestation(kp.public, att, beacon_sig=BSIG,
                                  presentation_binding=other, min_tier=AssuranceTier.AMBIENT)


def test_tier_below_minimum_is_rejected():
    kp = generate_sig_keypair()
    att = _att(kp, tier=AssuranceTier.AMBIENT)          # phone-only
    assert not verify_attestation(kp.public, att, beacon_sig=BSIG,
                                  presentation_binding=BINDING, min_tier=AssuranceTier.WEARABLE)


def test_freshness_bound_to_the_beacon_round_signature():
    kp = generate_sig_keypair()
    att = _att(kp)                                      # signed over BSIG
    stale = random_bytes(96)                            # a different round's signature
    assert not verify_attestation(kp.public, att, beacon_sig=stale,
                                  presentation_binding=BINDING, min_tier=AssuranceTier.AMBIENT)


def test_wrong_signer_rejected():
    kp, imposter = generate_sig_keypair(), generate_sig_keypair()
    att = _att(kp)
    assert not verify_attestation(imposter.public, att, beacon_sig=BSIG,
                                  presentation_binding=BINDING, min_tier=AssuranceTier.AMBIENT)
