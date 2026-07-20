"""drand quicknet BLS threshold-signature verification — known-answer tests against a real round
(League of Entropy round 1000000), so provenance can trust the beacon's authenticity, not just its
hash-consistency. Offline: the round is pinned, no network needed."""

import hashlib

import pytest

from atlas.beacon.drand import (
    DrandHTTPBeacon, QUICKNET_PUBLIC_KEY, verify_drand_signature,
)

# Real League-of-Entropy quicknet round (fetched once; pinned as a known-answer vector).
ROUND = 1_000_000
SIG = bytes.fromhex(
    "83ad29e4c409f9470fc2ef02f90214df49e02b441a1a241a82d622d9f608ef98fd8b11a029f1bee9d9e83b45088abe72")
RAND = bytes.fromhex("b22aad4794f7451896f7a371aa46106fd84d919f3f569acd5b2fddf1d1440af3")
PK = bytes.fromhex(QUICKNET_PUBLIC_KEY)


def _stub(round_number, sig, rand):
    return lambda url: {"round": round_number, "randomness": rand.hex(), "signature": sig.hex()}


# --------------------------------------------------------------------------- the verify itself
def test_real_round_verifies():
    assert verify_drand_signature(ROUND, SIG, PK) is True


def test_wrong_round_rejected():
    assert verify_drand_signature(ROUND + 1, SIG, PK) is False


def test_flipped_signature_rejected():
    bad = bytearray(SIG); bad[24] ^= 0x01
    assert verify_drand_signature(ROUND, bytes(bad), PK) is False


def test_malformed_inputs_fail_closed():
    assert verify_drand_signature(ROUND, b"", PK) is False
    assert verify_drand_signature(ROUND, SIG, b"\x00" * 96) is False


def test_hash_consistency_of_the_vector():
    assert RAND == hashlib.sha256(SIG).digest()          # sanity: randomness == H(signature)


# --------------------------------------------------------------------------- client integration
def test_beacon_accepts_authentic_round():
    b = DrandHTTPBeacon(http_get=_stub(ROUND, SIG, RAND))
    r = b.latest()
    assert r.round == ROUND and r.randomness == RAND


def test_beacon_rejects_relay_lying_about_the_round():
    # A relay returns the REAL signature + matching randomness (passes the hash check) but LIES
    # about the round number. Only the BLS check catches it.
    b = DrandHTTPBeacon(http_get=_stub(ROUND + 1, SIG, RAND))
    with pytest.raises(ValueError, match="BLS"):
        b.latest()


def test_bls_verification_can_be_disabled():
    # Escape hatch (e.g. offline stand-in): with verify_bls=False the lie is accepted.
    b = DrandHTTPBeacon(http_get=_stub(ROUND + 1, SIG, RAND), verify_bls=False)
    assert b.latest().round == ROUND + 1
