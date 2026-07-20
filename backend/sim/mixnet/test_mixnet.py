"""
Assertions that lock in the measured metadata-privacy effects.

    python -m sim.mixnet.test_mixnet      (from backend/, with '.' on path)
    # or: pytest sim/mixnet/test_mixnet.py
"""

from __future__ import annotations

import statistics

from sim.mixnet.core import (
    Relay, generate_traffic, link_accuracy, sender_identification,
    mean_anonymity_set, DEFAULT_BUCKETS, SINGLE_BUCKET,
)

TRIALS = 6
N, S, R, D, RW = 400, 20, 20, 60.0, 2.0


def _mean(fn):
    return statistics.mean(fn(t) for t in range(TRIALS))


def test_size_leakage_without_padding_is_high():
    acc = _mean(lambda t: link_accuracy(
        generate_traffic(N, S, R, D, seed=t),
        Relay(mode="none", seed=t).forward(generate_traffic(N, S, R, D, seed=t)),
        feature="size", seed=t))
    assert acc > 0.8, acc


def test_padding_kills_size_leakage():
    def one(t):
        msgs = generate_traffic(N, S, R, D, seed=t)
        outs = Relay(mode="padding", buckets=SINGLE_BUCKET, seed=t).forward(msgs)
        return link_accuracy(msgs, outs, feature="size", seed=t)
    acc = _mean(one)
    assert acc < 0.02, acc          # at/near 1/N chance


def test_timing_leakage_without_batching_is_high():
    def one(t):
        msgs = generate_traffic(N, S, R, D, seed=t)
        outs = Relay(mode="none", seed=t).forward(msgs)
        return link_accuracy(msgs, outs, feature="time", seed=t)
    assert _mean(one) > 0.6


def test_batching_kills_timing_leakage():
    def one(t):
        msgs = generate_traffic(N, S, R, D, seed=t)
        outs = Relay(mode="batching", round_window=RW, seed=t).forward(msgs)
        return link_accuracy(msgs, outs, feature="time", seed=t)
    assert _mean(one) < 0.1


def test_single_node_has_no_anonymity_set():
    def one(t):
        msgs = generate_traffic(N, 1, R, D, seed=t)
        outs = Relay(mode="both", buckets=SINGLE_BUCKET, round_window=RW, seed=t).forward(msgs)
        return sender_identification(outs), mean_anonymity_set(outs)
    res = [one(t) for t in range(TRIALS)]
    pid = statistics.mean(r[0] for r in res)
    anon = statistics.mean(r[1] for r in res)
    assert pid > 0.99, pid          # observer always names the (only) sender
    assert anon < 1.01, anon        # crowd of one


def test_federation_gives_anonymity_set():
    def one(t):
        msgs = generate_traffic(N, S, R, D, seed=t)
        outs = Relay(mode="both", buckets=SINGLE_BUCKET, round_window=RW, seed=t).forward(msgs)
        return sender_identification(outs), mean_anonymity_set(outs)
    res = [one(t) for t in range(TRIALS)]
    pid = statistics.mean(r[0] for r in res)
    anon = statistics.mean(r[1] for r in res)
    assert pid < 0.2, pid           # per-message sender guess far below 1.0
    assert anon > 5.0, anon         # real crowd


def test_both_kills_input_output_linking():
    def one(t):
        msgs = generate_traffic(N, S, R, D, seed=t)
        outs = Relay(mode="both", buckets=SINGLE_BUCKET, round_window=RW, seed=t).forward(msgs)
        return link_accuracy(msgs, outs, feature="both", seed=t)
    assert _mean(one) < 0.1


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS  {fn.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"FAIL  {fn.__name__}: {e}")
    print(f"\n{passed}/{len(fns)} passed")
