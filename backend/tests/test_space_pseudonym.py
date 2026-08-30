"""Tests for per-scope (space) pseudonyms (TRUST_LAYER.md #13)."""

import pytest

from atlas.crypto.primitives import random_bytes
from atlas.realid.space_pseudonym import (
    PersonhoodAuthority,
    PersonhoodError,
    SpaceRegistry,
    join_space,
    space_nullifier,
    space_nym,
    verify_personhood,
)

ROOT = b"system-id-root-secret-32-bytes.."
S1 = b"family"
S2 = b"workplace"


def test_stable_within_a_space():
    a = join_space(ROOT, S1)
    b = join_space(ROOT, S1)
    assert a == b                                   # deterministic: a consistent you in-space


def test_unlinkable_across_spaces():
    a = join_space(ROOT, S1)
    b = join_space(ROOT, S2)
    assert a.nym != b.nym and a.nullifier != b.nullifier


def test_different_roots_different_identities_same_space():
    other = random_bytes(32)
    assert space_nym(ROOT, S1) != space_nym(other, S1)
    assert space_nullifier(ROOT, S1) != space_nullifier(other, S1)


def test_nym_and_nullifier_are_domain_separated():
    # even for the same (root, space) the nym and nullifier differ (distinct labels), so
    # publishing nullifiers never reveals nyms.
    assert space_nym(ROOT, S1) != space_nullifier(ROOT, S1)


def test_non_revealing_of_root():
    m = join_space(ROOT, S1)
    assert ROOT not in m.nym and ROOT not in m.nullifier


# --------------------------------------------------------------------------- personhood / sybil
def _authority(*roots):
    a = PersonhoodAuthority()
    for r in roots:
        a.enroll(r)
    return a


def test_registry_one_identity_per_human_and_idempotent_rejoin():
    auth = _authority(ROOT)
    reg = SpaceRegistry(S1, auth.root_digest)
    proof = auth.membership_proof(ROOT)
    reg.register(ROOT, proof)
    reg.register(ROOT, proof)                       # idempotent (same nullifier)
    assert reg.size() == 1 and reg.is_member(space_nym(ROOT, S1))


def test_registry_counts_distinct_verified_humans():
    roots = [random_bytes(32) for _ in range(4)]
    auth = _authority(*roots)
    reg = SpaceRegistry(S1, auth.root_digest)
    for r in roots:
        reg.register(r, auth.membership_proof(r))
    assert reg.size() == 4


def test_unverified_roots_are_rejected_the_critical_fix():
    # THE sybil fix: 1000 random, unenrolled roots admit ZERO identities (previously 1000).
    auth = _authority(ROOT)                          # only ROOT is verified
    reg = SpaceRegistry(S1, auth.root_digest)
    for _ in range(1000):
        with pytest.raises(PersonhoodError):
            r = random_bytes(32)
            reg.register(r, auth.membership_proof(r))  # not enrolled -> proof raises
    assert reg.size() == 0


def test_forged_membership_proof_is_rejected():
    auth = _authority(ROOT)
    reg = SpaceRegistry(S1, auth.root_digest)
    fake_root = random_bytes(32)
    # a made-up proof for an unenrolled root does not verify against the authority digest.
    bogus_proof = [(random_bytes(32), True)]
    with pytest.raises(PersonhoodError):
        reg.register(fake_root, bogus_proof)
    assert reg.size() == 0


def test_a_single_human_cannot_mint_two_identities_in_one_space():
    auth = _authority(ROOT)
    reg = SpaceRegistry(S1, auth.root_digest)
    proof = auth.membership_proof(ROOT)
    reg.register(ROOT, proof)
    reg.register(ROOT, proof)
    assert reg.size() == 1


def test_personhood_proof_verifies_and_wrong_authority_fails():
    auth = _authority(ROOT, random_bytes(32))
    assert verify_personhood(ROOT, auth.membership_proof(ROOT), auth.root_digest)
    assert not verify_personhood(ROOT, auth.membership_proof(ROOT), random_bytes(32))  # wrong root digest
