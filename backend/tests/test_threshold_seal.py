"""Adversarial tests for the threshold biometric-key seal (TRUST_LAYER.md #1/#2).

Properties asserted:
  * round-trip: user_half ∧ m-of-n custodians reopens the sketch;
  * m-of-n threshold: m-1 shares FAIL, any m shares succeed, extra shares fine;
  * fail-closed on every wrong factor: bad user_half, wrong-user shares, tampered
    ciphertext, mismatched context — all RAISE, none silently degrade;
  * ciphertext-anywhere (#2): confidentiality is independent of the declared storage
    location; the same ciphertext opens regardless of where it was "kept";
  * no low-entropy secret: the custodian secret is fresh CSPRNG, so two seals of the same
    plaintext differ (semantic security) and there is nothing password-derived to grind.
"""

import itertools

import pytest

from atlas.crypto.primitives import random_bytes
from atlas.recovery.threshold_seal import (
    Custodian,
    CustodianShare,
    SealedSketch,
    StorageLocation,
    ThresholdNotMet,
    ThresholdPolicy,
    UnsealFailed,
    seal,
    unseal,
)

SECRET = b"biometric-enrollment-or-any-sealed-material"
UH = b"U" * 32          # a full-entropy 32-byte user half (TSK-bound)
UH2 = b"W" * 32         # a DIFFERENT full-entropy half


def _custodians(n: int) -> list[Custodian]:
    return [Custodian(label=f"custodian-{i}") for i in range(n)]


def _seal(secret=SECRET, *, user_half=UH, n=5, m=3,
          storage=StorageLocation.GUARDIANS, context=b"ctx"):
    policy = ThresholdPolicy(n=n, m=m)
    return seal(secret, user_half=user_half, custodians=_custodians(n),
                policy=policy, storage=storage, context=context)


# --------------------------------------------------------------------------- round-trip
def test_round_trip_exact_threshold():
    user_half = UH
    sealed, shares = _seal(user_half=user_half, n=5, m=3)
    assert unseal(sealed, user_half=user_half, custodian_shares=shares[:3]) == SECRET


def test_round_trip_any_m_subset():
    user_half = UH
    sealed, shares = _seal(user_half=user_half, n=5, m=3)
    # EVERY 3-of-5 subset must reconstruct — not just the first m.
    for subset in itertools.combinations(shares, 3):
        assert unseal(sealed, user_half=user_half,
                      custodian_shares=list(subset)) == SECRET


def test_more_than_threshold_ok():
    user_half = UH
    sealed, shares = _seal(user_half=user_half, n=5, m=3)
    assert unseal(sealed, user_half=user_half, custodian_shares=shares) == SECRET


# --------------------------------------------------------------------------- threshold
def test_below_threshold_raises():
    user_half = UH
    sealed, shares = _seal(user_half=user_half, n=5, m=3)
    with pytest.raises(ThresholdNotMet):
        unseal(sealed, user_half=user_half, custodian_shares=shares[:2])


def test_one_of_one_policy_rejected():
    # A threshold needs a real quorum; m=1 is not a threshold. Storing everything
    # yourself is StorageLocation.SELF, not an m=1 policy.
    with pytest.raises(ValueError):
        ThresholdPolicy(n=1, m=1)
    with pytest.raises(ValueError):
        ThresholdPolicy(n=3, m=1)


def test_policy_n_mismatch_rejected():
    policy = ThresholdPolicy(n=5, m=3)
    with pytest.raises(ValueError):
        seal(SECRET, user_half=UH, custodians=_custodians(4),  # 4 != n=5
             policy=policy, storage=StorageLocation.SELF)


# ------------------------------------------------------------------- fail-closed factors
def test_wrong_user_half_fails():
    sealed, shares = _seal(user_half=UH)
    with pytest.raises(UnsealFailed):
        unseal(sealed, user_half=UH2, custodian_shares=shares[:3])


def test_missing_user_half_fails():
    sealed, shares = _seal(user_half=UH)
    with pytest.raises(UnsealFailed):
        unseal(sealed, user_half=b"", custodian_shares=shares[:3])


def test_seal_rejects_empty_or_low_entropy_user_half():
    # B4 fix: sealing with an empty half would collapse the two-factor to custodian-quorum-only,
    # and a PIN-length half is offline-brute-forceable by anyone holding m shares. Fail closed at
    # SEAL so a degenerate one-factor seal can never be created.
    for weak in (b"", b"1234", b"hunter2", b"short-half"):
        with pytest.raises(ValueError):
            _seal(user_half=weak)
    # a genuine full-entropy half seals fine
    sealed, shares = _seal(user_half=UH)
    assert unseal(sealed, user_half=UH, custodian_shares=shares[:3]) == SECRET


def test_shares_from_a_different_seal_fail():
    user_half = UH
    sealed, _ = _seal(user_half=user_half)
    _, other_shares = _seal(user_half=user_half)  # independent custodian secret
    with pytest.raises(UnsealFailed):
        unseal(sealed, user_half=user_half, custodian_shares=other_shares[:3])


def test_tampered_ciphertext_fails():
    user_half = UH
    sealed, shares = _seal(user_half=user_half)
    flipped = bytearray(sealed.ciphertext)
    flipped[-1] ^= 0x01
    tampered = SealedSketch(ciphertext=bytes(flipped), storage=sealed.storage,
                            policy=sealed.policy, context=sealed.context)
    with pytest.raises(UnsealFailed):
        unseal(tampered, user_half=user_half, custodian_shares=shares[:3])


def test_wrong_context_fails():
    user_half = UH
    sealed, shares = _seal(user_half=user_half, context=b"ctx-A")
    moved = SealedSketch(ciphertext=sealed.ciphertext, storage=sealed.storage,
                         policy=sealed.policy, context=b"ctx-B")  # rebind attempt
    with pytest.raises(UnsealFailed):
        unseal(moved, user_half=user_half, custodian_shares=shares[:3])


# ------------------------------------------------------- ciphertext-anywhere (#2)
def test_storage_location_does_not_affect_confidentiality():
    user_half = UH
    # Same inputs, differing only in declared storage -> unseal identically.
    for storage in StorageLocation:
        sealed, shares = _seal(user_half=user_half, storage=storage)
        assert unseal(sealed, user_half=user_half,
                      custodian_shares=shares[:3]) == SECRET


def test_relabelling_storage_after_seal_changes_nothing():
    # Moving a sketch (rewriting only its storage tag) neither helps nor hurts: the
    # ciphertext is unchanged and still opens with the same factors.
    user_half = UH
    sealed, shares = _seal(user_half=user_half, storage=StorageLocation.SELF)
    moved = SealedSketch(ciphertext=sealed.ciphertext,
                         storage=StorageLocation.SERVER_SHARDED,  # "uploaded"
                         policy=sealed.policy, context=sealed.context)
    assert unseal(moved, user_half=user_half, custodian_shares=shares[:3]) == SECRET


# ------------------------------------------------------------------- semantic security
def test_two_seals_of_same_plaintext_differ():
    user_half = UH
    a, _ = _seal(user_half=user_half)
    b, _ = _seal(user_half=user_half)
    assert a.ciphertext != b.ciphertext  # fresh custodian secret + AEAD nonce each time


def test_custodian_label_is_opaque_and_carried():
    # Guardianship (#4) keeps the real set private; the seal only carries opaque handles
    # + the institutional flag it will enforce invariants on.
    policy = ThresholdPolicy(n=3, m=2)
    custodians = [Custodian("home", institutional=False),
                  Custodian("op-eu", institutional=True),
                  Custodian("op-us", institutional=True)]
    _, shares = seal(SECRET, user_half=UH, custodians=custodians,
                     policy=policy, storage=StorageLocation.SERVER_SHARDED)
    assert [cs.custodian.institutional for cs in shares] == [False, True, True]
