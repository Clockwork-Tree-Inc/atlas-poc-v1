"""Tests for the OPRF hardening (TRUST_LAYER.md #3).

Properties:
  * CORRECTNESS: the oblivious client run equals the non-oblivious oracle F(k, input).
  * PRF: deterministic in the input, independent of the (random) blind; distinct inputs ->
    distinct outputs; wrong key -> different output.
  * OBLIVIOUSNESS (structural): the server sees only a blinded element that is re-randomized
    every run, so it carries no information about the input.
  * SHARDING: additive n-of-n shares reconstruct the same F; a single shard cannot evaluate it.
  * PROACTIVE REFRESH: a sharing-of-zero rotates every share yet leaves F unchanged.
  * NO OFFLINE GRIND: F cannot be computed without the shards (that is the whole point).
"""

import pytest

from atlas.recovery import oprf


def test_oblivious_equals_oracle():
    k = oprf.keygen()
    shard = oprf.OPRFShard(key_share=k)          # 1-of-1: the share IS the key
    x = b"name|password"
    assert oprf.evaluate_oblivious([shard], x) == oprf.evaluate_full(k, x)


def test_prf_is_deterministic_and_blind_independent():
    k = oprf.keygen()
    shard = oprf.OPRFShard(key_share=k)
    x = b"selector"
    # two runs use independent random blinds internally, yet yield the SAME output
    assert oprf.evaluate_oblivious([shard], x) == oprf.evaluate_oblivious([shard], x)


def test_distinct_inputs_distinct_outputs():
    k = oprf.keygen()
    shard = oprf.OPRFShard(key_share=k)
    assert oprf.evaluate_oblivious([shard], b"alice|pw") != oprf.evaluate_oblivious([shard], b"bob|pw")


def test_wrong_key_changes_output():
    x = b"selector"
    a = oprf.OPRFShard(key_share=oprf.keygen())
    b = oprf.OPRFShard(key_share=oprf.keygen())
    assert oprf.evaluate_oblivious([a], x) != oprf.evaluate_oblivious([b], x)


def test_blinding_is_rerandomized_each_run():
    x = b"same input"
    b1, r1 = oprf.blind(x)
    b2, r2 = oprf.blind(x)
    # the server-visible blinded element differs every time -> reveals nothing about x
    assert b1 != b2 and r1 != r2


def test_sharding_reconstructs_same_prf():
    k = oprf.keygen()
    x = b"name|password"
    full = oprf.evaluate_full(k, x)
    for n in (1, 2, 3, 5):
        shards = [oprf.OPRFShard(key_share=s) for s in oprf.split_key(k, n)]
        assert oprf.evaluate_oblivious(shards, x) == full


def test_a_single_shard_cannot_evaluate_the_prf():
    k = oprf.keygen()
    x = b"name|password"
    shares = oprf.split_key(k, 3)
    full = oprf.evaluate_full(k, x)
    # any strict subset of shards yields a DIFFERENT output (shares are additive n-of-n)
    for subset in ([0], [0, 1], [1, 2]):
        shards = [oprf.OPRFShard(key_share=shares[i]) for i in subset]
        assert oprf.evaluate_oblivious(shards, x) != full


def test_proactive_refresh_preserves_the_function():
    k = oprf.keygen()
    x = b"name|password"
    shares = oprf.split_key(k, 3)
    refreshed = oprf.proactive_refresh(shares)
    assert refreshed != shares                                   # every share rotated
    assert sum(refreshed) % oprf._Q == sum(shares) % oprf._Q     # ...but the key is unchanged
    before = oprf.evaluate_oblivious([oprf.OPRFShard(s) for s in shares], x)
    after = oprf.evaluate_oblivious([oprf.OPRFShard(s) for s in refreshed], x)
    assert before == after == oprf.evaluate_full(k, x)


def test_client_cannot_grind_without_the_shards():
    # The whole point: without the shard(s), a client holding only the input cannot compute F.
    # Model "no server" as an empty shard set -> combine refuses (nothing to grind against).
    with pytest.raises(oprf.OPRFError):
        oprf.evaluate_oblivious([], b"guess")


def test_blinded_element_is_rejected_if_out_of_range():
    shard = oprf.OPRFShard(key_share=oprf.keygen())
    with pytest.raises(oprf.OPRFError):
        shard.evaluate(1)                    # degenerate element
    with pytest.raises(oprf.OPRFError):
        shard.evaluate(oprf._P)              # out of range


def test_small_subgroup_element_is_rejected():
    # the order-2 element P-1 would leak 1 bit of key-share parity per query; now rejected
    # by the prime-order subgroup check (element^Q == 1).
    shard = oprf.OPRFShard(key_share=oprf.keygen())
    assert not oprf._in_subgroup(oprf._P - 1)
    with pytest.raises(oprf.OPRFError):
        shard.evaluate(oprf._P - 1)
    with pytest.raises(oprf.OPRFError):
        oprf.combine_partials([oprf._P - 1])


def test_deterministic_kat_with_fixed_blind():
    # Pin the group math: a fixed key + fixed input + fixed blind reproduces a fixed transcript.
    k = 0x1234567890ABCDEF
    x = b"kat-input"
    r = 0xCAFEBABE
    h = oprf.hash_to_group(x)
    blinded = pow(h, r, oprf._P)
    evaluated = oprf.OPRFShard(k).evaluate(blinded)
    unblinded = oprf.unblind(evaluated, r)
    assert unblinded == pow(h, k, oprf._P)                    # h^k recovered
    assert oprf.finalize(x, unblinded) == oprf.evaluate_full(k, x)
