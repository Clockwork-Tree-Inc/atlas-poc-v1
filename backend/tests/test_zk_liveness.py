"""Adversarial tests for the ZK proof-of-liveness (TRUST_LAYER.md #14).

Asserts the three properties that make it a REAL proof:
  * COMPLETENESS — an honest prover with score >= threshold verifies (incl. the boundary).
  * SOUNDNESS — a prover with score < threshold cannot construct a proof; and any tamper
    (flipped commitment, corrupted response, changed threshold/context) fails verification.
  * ZERO-KNOWLEDGE / HIDING — proofs are randomised, carry no plaintext score, and different
    scores are indistinguishable beyond ">= threshold".
"""

import dataclasses

import pytest

from atlas.zk.liveness_proof import (
    ZKError,
    prove_liveness,
    verify_liveness,
)

BITS = 16


# --------------------------------------------------------------------------- completeness
def test_honest_proof_verifies():
    pf = prove_liveness(score=1000, threshold=800, bits=BITS)
    assert verify_liveness(pf)


def test_boundary_score_equals_threshold():
    pf = prove_liveness(score=800, threshold=800, bits=BITS)   # w - tau = 0
    assert verify_liveness(pf)


def test_large_margin():
    pf = prove_liveness(score=800 + (1 << BITS) - 1, threshold=800, bits=BITS)  # top of range
    assert verify_liveness(pf)


# --------------------------------------------------------------------------- range / prover honesty
def test_prover_cannot_prove_below_threshold():
    # a cheating prover with score < threshold cannot even build a proof (v would be negative).
    with pytest.raises(ZKError):
        prove_liveness(score=799, threshold=800, bits=BITS)


def test_score_above_provable_range_rejected():
    with pytest.raises(ZKError):
        prove_liveness(score=800 + (1 << BITS), threshold=800, bits=BITS)


# --------------------------------------------------------------------------- soundness / tamper
def test_flipped_bit_commitment_fails():
    pf = prove_liveness(score=1000, threshold=800, bits=BITS)
    bad_commits = list(pf.bit_commitments)
    bad_commits[3] = (bad_commits[3] * 7) % _P()
    tampered = dataclasses.replace(pf, bit_commitments=bad_commits)
    assert not verify_liveness(tampered)


def test_corrupted_response_fails():
    pf = prove_liveness(score=1000, threshold=800, bits=BITS)
    bad_proofs = list(pf.bit_proofs)
    bad_proofs[0] = dataclasses.replace(bad_proofs[0], z0=(bad_proofs[0].z0 + 1))
    tampered = dataclasses.replace(pf, bit_proofs=bad_proofs)
    assert not verify_liveness(tampered)


def test_raising_the_claimed_threshold_fails():
    # a proof for threshold=800 must NOT verify if the claimed threshold is bumped up (the
    # committed value would no longer reconstruct the stored commitment).
    pf = prove_liveness(score=1000, threshold=800, bits=BITS)
    forged = dataclasses.replace(pf, threshold=900)
    assert not verify_liveness(forged)


def test_context_binding():
    pf = prove_liveness(score=1000, threshold=800, bits=BITS, context=b"session-A")
    rebinded = dataclasses.replace(pf, context=b"session-B")
    assert not verify_liveness(rebinded)


def test_wrong_length_fails():
    pf = prove_liveness(score=1000, threshold=800, bits=BITS)
    assert not verify_liveness(dataclasses.replace(pf, bit_commitments=pf.bit_commitments[:-1]))


# --------------------------------------------------------------------------- zero-knowledge / hiding
def test_proofs_are_randomised():
    a = prove_liveness(score=1000, threshold=800, bits=BITS)
    b = prove_liveness(score=1000, threshold=800, bits=BITS)
    assert a.commitment != b.commitment            # fresh blinding each time
    assert a.bit_commitments != b.bit_commitments
    assert verify_liveness(a) and verify_liveness(b)


def test_proof_carries_no_plaintext_score():
    score = 1234
    pf = prove_liveness(score=score, threshold=800, bits=BITS)
    # the score never appears as a field; only the threshold (public) and opaque group elements.
    assert score not in (pf.threshold, pf.bits)
    assert score not in pf.bit_commitments and score != pf.commitment


def test_different_scores_both_verify_indistinguishably():
    # the verifier cannot tell 900 from 5000 — both only prove ">= 800".
    lo = prove_liveness(score=900, threshold=800, bits=BITS)
    hi = prove_liveness(score=5000, threshold=800, bits=BITS)
    assert verify_liveness(lo) and verify_liveness(hi)
    assert lo.commitment != hi.commitment           # distinct commitments, both hiding


def test_out_of_subgroup_commitment_is_rejected():
    # a malicious prover swaps a bit commitment for the order-2 element P-1 and fixes up the
    # aggregate commitment so the linear check passes — the subgroup check must still reject it.
    from atlas.zk.liveness_proof import G, P, Q, _combine_bits
    pf = prove_liveness(score=1000, threshold=800, bits=BITS)
    bad = list(pf.bit_commitments)
    bad[0] = P - 1                                     # not in the prime-order subgroup
    consistent_commitment = (pow(G, pf.threshold % Q, P) * _combine_bits(bad)) % P
    tampered = dataclasses.replace(pf, bit_commitments=bad, commitment=consistent_commitment)
    assert not verify_liveness(tampered)


def _P():
    from atlas.zk.liveness_proof import P
    return P
