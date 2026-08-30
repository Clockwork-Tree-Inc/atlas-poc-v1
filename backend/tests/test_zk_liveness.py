"""Adversarial tests for the ZK proof-of-liveness (TRUST_LAYER.md #14).

Asserts the properties that make it a REAL proof:
  * COMPLETENESS — an honest prover with score >= threshold verifies (incl. the boundary).
  * SOUNDNESS — a prover with score < threshold cannot construct a proof; any tamper fails; and the
    VERIFIER chooses the threshold + binds a fresh context (a prover cannot pick a low bar or replay).
  * ZERO-KNOWLEDGE / HIDING — proofs are randomised, carry no plaintext score, and different scores
    are indistinguishable beyond ">= threshold".
"""

import dataclasses

import pytest

from atlas.zk.liveness_proof import ZKError, prove_liveness, verify_liveness

BITS = 16
TAU = 800   # the verifier's required threshold throughout


# --------------------------------------------------------------------------- completeness
def test_honest_proof_verifies():
    pf = prove_liveness(score=1000, threshold=TAU, bits=BITS)
    assert verify_liveness(pf, required_threshold=TAU)


def test_boundary_score_equals_threshold():
    pf = prove_liveness(score=800, threshold=TAU, bits=BITS)   # w - tau = 0
    assert verify_liveness(pf, required_threshold=TAU)


def test_large_margin():
    pf = prove_liveness(score=800 + (1 << BITS) - 1, threshold=TAU, bits=BITS)  # top of range
    assert verify_liveness(pf, required_threshold=TAU)


# --------------------------------------------------------------------------- range / prover honesty
def test_prover_cannot_prove_below_threshold():
    with pytest.raises(ZKError):
        prove_liveness(score=799, threshold=TAU, bits=BITS)


def test_score_above_provable_range_rejected():
    with pytest.raises(ZKError):
        prove_liveness(score=800 + (1 << BITS), threshold=TAU, bits=BITS)


# --------------------------------------------------------------------------- verifier chooses the bar
def test_verifier_floor_rejects_prover_chosen_low_threshold():
    # a cheating prover makes an HONEST proof for a threshold of 0 (w >= 0, trivially true)...
    pf = prove_liveness(score=1000, threshold=0, bits=BITS)
    assert verify_liveness(pf, required_threshold=0)          # verifiable at bar 0
    # ...but a verifier that REQUIRES 800 rejects it: the prover cannot pick its own low bar
    assert not verify_liveness(pf, required_threshold=TAU)


def test_replay_rejected_by_expected_context():
    pf = prove_liveness(score=1000, threshold=TAU, bits=BITS, context=b"epoch-7:nonceX")
    assert verify_liveness(pf, required_threshold=TAU, expected_context=b"epoch-7:nonceX")
    # a different epoch/nonce (a replay to another session/verifier) is rejected
    assert not verify_liveness(pf, required_threshold=TAU, expected_context=b"epoch-8:nonceY")


# --------------------------------------------------------------------------- soundness / tamper
def test_flipped_bit_commitment_fails():
    pf = prove_liveness(score=1000, threshold=TAU, bits=BITS)
    bad_commits = list(pf.bit_commitments)
    bad_commits[3] = (bad_commits[3] * 7) % _P()
    tampered = dataclasses.replace(pf, bit_commitments=bad_commits)
    assert not verify_liveness(tampered, required_threshold=TAU)


def test_corrupted_response_fails():
    pf = prove_liveness(score=1000, threshold=TAU, bits=BITS)
    bad_proofs = list(pf.bit_proofs)
    bad_proofs[0] = dataclasses.replace(bad_proofs[0], z0=(bad_proofs[0].z0 + 1))
    tampered = dataclasses.replace(pf, bit_proofs=bad_proofs)
    assert not verify_liveness(tampered, required_threshold=TAU)


def test_raising_the_claimed_threshold_fails():
    pf = prove_liveness(score=1000, threshold=TAU, bits=BITS)
    forged = dataclasses.replace(pf, threshold=900)
    assert not verify_liveness(forged, required_threshold=TAU)   # commitment no longer reconstructs


def test_context_binding():
    pf = prove_liveness(score=1000, threshold=TAU, bits=BITS, context=b"session-A")
    rebinded = dataclasses.replace(pf, context=b"session-B")
    assert not verify_liveness(rebinded, required_threshold=TAU, expected_context=b"session-A")


def test_wrong_length_fails():
    pf = prove_liveness(score=1000, threshold=TAU, bits=BITS)
    assert not verify_liveness(dataclasses.replace(pf, bit_commitments=pf.bit_commitments[:-1]),
                               required_threshold=TAU)


# --------------------------------------------------------------------------- zero-knowledge / hiding
def test_proofs_are_randomised():
    a = prove_liveness(score=1000, threshold=TAU, bits=BITS)
    b = prove_liveness(score=1000, threshold=TAU, bits=BITS)
    assert a.commitment != b.commitment            # fresh blinding each time
    assert a.bit_commitments != b.bit_commitments
    assert verify_liveness(a, required_threshold=TAU) and verify_liveness(b, required_threshold=TAU)


def test_proof_carries_no_plaintext_score():
    score = 1234
    pf = prove_liveness(score=score, threshold=TAU, bits=BITS)
    assert score not in (pf.threshold, pf.bits)
    assert score not in pf.bit_commitments and score != pf.commitment


def test_different_scores_both_verify_indistinguishably():
    lo = prove_liveness(score=900, threshold=TAU, bits=BITS)
    hi = prove_liveness(score=5000, threshold=TAU, bits=BITS)
    assert verify_liveness(lo, required_threshold=TAU) and verify_liveness(hi, required_threshold=TAU)
    assert lo.commitment != hi.commitment


def test_out_of_subgroup_commitment_is_rejected():
    from atlas.zk.liveness_proof import G, P, Q, _combine_bits
    pf = prove_liveness(score=1000, threshold=TAU, bits=BITS)
    bad = list(pf.bit_commitments)
    bad[0] = P - 1                                     # not in the prime-order subgroup
    consistent_commitment = (pow(G, pf.threshold % Q, P) * _combine_bits(bad)) % P
    tampered = dataclasses.replace(pf, bit_commitments=bad, commitment=consistent_commitment)
    assert not verify_liveness(tampered, required_threshold=TAU)


def test_attested_score_binds_to_the_attester():
    from atlas.crypto.sign import generate_sig_keypair
    attester = generate_sig_keypair()                       # the ring / Secure Enclave that measured the score
    pf = prove_liveness(score=1000, threshold=TAU, bits=BITS, attester=attester)
    assert verify_liveness(pf, required_threshold=TAU, attester_public=attester.public)
    # a verifier requiring attestation REJECTS an unattested proof (prover-invented score)
    unattested = prove_liveness(score=1000, threshold=TAU, bits=BITS)
    assert not verify_liveness(unattested, required_threshold=TAU, attester_public=attester.public)
    # ...and rejects a proof attested by a DIFFERENT attester (not the trusted measurer)
    other = generate_sig_keypair()
    assert not verify_liveness(pf, required_threshold=TAU, attester_public=other.public)
    # with no attester required, the proof still verifies (backward compatible)
    assert verify_liveness(pf, required_threshold=TAU)


def _P():
    from atlas.zk.liveness_proof import P
    return P
