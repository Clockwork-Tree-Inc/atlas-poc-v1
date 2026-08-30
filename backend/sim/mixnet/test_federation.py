"""
Assertions that lock in the FEDERATION + COVER-TRAFFIC results: the
anonymity-set gap left open by a single self-owned node is closed.

    python -m sim.mixnet.test_federation    (from backend/, with '.' on path)
    # or: pytest sim/mixnet/test_federation.py
"""

from __future__ import annotations

import statistics

from sim.mixnet.federation import (
    Federation, build_real_packets,
    sender_identification, mean_anonymity_set,
    both_ends_violations, relay_endpoint_view,
    activity_detection_accuracy,
)

TRIALS = 6
N, S, R, D, RW, RELAYS = 600, 20, 20, 60.0, 1.0, 5


def _fed(n_senders, hops, seed):
    pk = build_real_packets(N, n_senders, R, D, seed=seed)
    return Federation(num_relays=RELAYS, hops=hops, round_window=RW, seed=seed).route(pk)


def _mean(fn):
    return statistics.mean(fn(t) for t in range(TRIALS))


# -- 1. ANONYMITY SET ------------------------------------------------------- #

def test_single_node_has_no_anonymity_set():
    """The baseline gap: 1 sender, 1 hop -> anonymity set of one, 100% id."""
    def one(t):
        pk = build_real_packets(N, 1, R, D, seed=t)
        st = Federation(num_relays=1, hops=1, round_window=RW, seed=t).route(pk)
        return sender_identification(st), mean_anonymity_set(st)
    res = [one(t) for t in range(TRIALS)]
    assert statistics.mean(r[0] for r in res) > 0.99      # observer always right
    assert statistics.mean(r[1] for r in res) < 1.01      # crowd of one


def test_federation_delivers_real_anonymity_set():
    """N=20 senders, H=3 hops -> per-message sender id in the ~1/N range and a
    real (double-digit) crowd -- the gap is closed."""
    res = [_fed_metrics(20, 3, t) for t in range(TRIALS)]
    pid = statistics.mean(r[0] for r in res)
    anon = statistics.mean(r[1] for r in res)
    assert pid < 0.1, pid            # far below the single-node 1.0 (target 0.05-0.1)
    assert anon > 10.0, anon         # real crowd, not a set of one


def _fed_metrics(n_senders, hops, seed):
    st = _fed(n_senders, hops, seed)
    return sender_identification(st), mean_anonymity_set(st)


def test_more_hops_grow_the_anonymity_set():
    """Each extra independent hop unions more crowds: anon set strictly grows,
    sender-id strictly falls."""
    a = [_mean(lambda t: mean_anonymity_set(_fed(20, h, t))) for h in (1, 2, 3)]
    p = [_mean(lambda t: sender_identification(_fed(20, h, t))) for h in (1, 2, 3)]
    assert a[0] < a[1] < a[2], a
    assert p[0] > p[1] > p[2], p


def test_sender_id_tracks_one_over_N():
    """Across a federation the sender-id probability scales like ~1/N."""
    p20 = _mean(lambda t: sender_identification(_fed(20, 3, t)))
    p5 = _mean(lambda t: sender_identification(_fed(5, 3, t)))
    assert p5 > p20                              # smaller crowd -> easier
    assert abs(p20 - 1.0 / 20) < 0.03, p20       # near 1/N
    assert abs(p5 - 1.0 / 5) < 0.03, p5


# -- 2. NO SINGLE POINT SEES BOTH ENDS -------------------------------------- #

def test_single_hop_relay_sees_both_ends():
    """H=1 is exactly the single-node situation: the one relay links every
    (sender, recipient) pair."""
    st = _fed(20, 1, 42)
    assert both_ends_violations(st) == len(st["packets"])


def test_multihop_no_relay_sees_both_ends():
    """With H>=2 independent hops no single relay ever observes a true sender
    endpoint and a true recipient endpoint for the same message."""
    for h in (2, 3):
        for t in range(TRIALS):
            st = _fed(20, h, 100 + t)
            assert both_ends_violations(st) == 0
            for r, v in relay_endpoint_view(st).items():
                assert v["both"] == 0, (h, r, v)


# -- 3. COVER TRAFFIC closes activity timing -------------------------------- #

def test_no_cover_leaks_activity():
    acc = activity_detection_accuracy(0.0, mu_active=8.0, mu_idle=0.0,
                                      trials=20000, seed=1)
    assert acc > 0.95, acc           # active link is obvious


def test_cover_traffic_closes_activity_timing():
    """A constant-rate cover budget >= the real load drives the observer's
    active-vs-idle 2AFC accuracy back to chance (0.5)."""
    acc = activity_detection_accuracy(16.0, mu_active=8.0, mu_idle=0.0,
                                      trials=40000, seed=2)
    assert abs(acc - 0.5) < 0.02, acc     # indistinguishable from chance


# -- 4. COST is real and bounded (the price, measured) ---------------------- #

def test_latency_is_hops_times_round():
    """Latency is ~ H x round window: the honest price of the mix cascade."""
    def mean_lat(h, t):
        st = _fed(20, h, 500 + t)
        return statistics.mean(p.deliver_time - p.send_time for p in st["packets"])
    l1 = _mean(lambda t: mean_lat(1, t))
    l3 = _mean(lambda t: mean_lat(3, t))
    assert l3 > l1                                   # more hops cost more latency
    assert abs(l3 - 3 * (RW / 2 + RW / 2)) < 0.6     # ~ H x round window


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS  {fn.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"FAIL  {fn.__name__}: {e}")
    print(f"\n{passed}/{len(fns)} passed")
