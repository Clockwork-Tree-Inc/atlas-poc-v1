"""
Run the four measurements and print the numbers.

    python -m sim.mixnet.run_measurements      (from backend/, with '.' on path)
"""

from __future__ import annotations

import statistics

from sim.mixnet.core import (
    Relay, generate_traffic, link_accuracy, sender_identification,
    mean_anonymity_set, latency_stats, DEFAULT_BUCKETS, SINGLE_BUCKET,
)

TRIALS = 8           # average over independent traffic samples
N_MSGS = 400
N_SENDERS = 20
N_RECIP = 20
DURATION = 60.0
ROUND = 2.0          # batching window (s)


def _avg(fn):
    vals = [fn(t) for t in range(TRIALS)]
    return statistics.mean(vals), (statistics.pstdev(vals) if len(vals) > 1 else 0.0)


def _run(mode, feature, buckets=DEFAULT_BUCKETS, round_window=ROUND,
         n_senders=N_SENDERS, n_msgs=N_MSGS):
    def one(t):
        msgs = generate_traffic(n_msgs, n_senders, N_RECIP, DURATION, seed=1000 + t)
        relay = Relay(mode=mode, buckets=buckets, round_window=round_window, seed=7000 + t)
        outs = relay.forward(msgs)
        return link_accuracy(msgs, outs, feature=feature, seed=9000 + t)
    return _avg(one)


def hr(title):
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def main():
    chance = 1.0 / N_MSGS
    print(f"Config: {N_MSGS} msgs, {N_SENDERS} senders, {N_RECIP} recipients, "
          f"{DURATION:.0f}s, round={ROUND:.0f}s, {TRIALS} trials")
    print(f"Random-guess baseline for input->output linking = 1/{N_MSGS} = {chance:.4f}")

    # -- 1. SIZE LEAKAGE ---------------------------------------------------- #
    hr("1. SIZE LEAKAGE  (observer uses SIZE only)")
    m, s = _run("none", "size")
    print(f"  no padding            link acc = {m:.3f} +/- {s:.3f}")
    m, s = _run("padding", "size", buckets=DEFAULT_BUCKETS)
    print(f"  padding (6 buckets)   link acc = {m:.3f} +/- {s:.3f}")
    m, s = _run("padding", "size", buckets=SINGLE_BUCKET)
    print(f"  padding (1 bucket)    link acc = {m:.3f} +/- {s:.3f}   (chance={chance:.4f})")

    # -- 2. TIMING LEAKAGE -------------------------------------------------- #
    hr("2. TIMING LEAKAGE  (observer uses TIMING/order only)")
    m, s = _run("none", "time")
    print(f"  no batching           link acc = {m:.3f} +/- {s:.3f}")
    m, s = _run("batching", "time", round_window=ROUND)
    print(f"  batching (round={ROUND:.0f}s) link acc = {m:.3f} +/- {s:.3f}")
    # per-batch chance:
    def batchsz(t):
        msgs = generate_traffic(N_MSGS, N_SENDERS, N_RECIP, DURATION, seed=1000 + t)
        outs = Relay(mode="batching", round_window=ROUND, seed=7000 + t).forward(msgs)
        import collections
        c = collections.Counter(m.out_time for m in outs)
        return statistics.mean(c.values())
    bs, _ = _avg(batchsz)
    print(f"  mean batch size = {bs:.1f} msgs  => within-batch chance ~ 1/{bs:.1f} = {1/bs:.3f}")

    # -- 3. ANONYMITY SET: single node vs federation ------------------------ #
    hr("3. ANONYMITY SET  (both padding+batching on; SENDER identification)")
    print("  Shape is normalized either way. Question: can observer still name the sender?")
    print(f"  {'senders':>8} | {'link(both)':>11} | {'anon.set':>9} | {'P(sender)':>10} | {'1/N':>7}")
    for n in [1, 2, 5, 10, 20, 50]:
        def one(t):
            msgs = generate_traffic(N_MSGS, n, N_RECIP, DURATION, seed=2000 + t)
            relay = Relay(mode="both", buckets=SINGLE_BUCKET, round_window=ROUND, seed=8000 + t)
            outs = relay.forward(msgs)
            link = link_accuracy(msgs, outs, feature="both", seed=9500 + t)
            pid = sender_identification(outs)
            anon = mean_anonymity_set(outs)
            return link, pid, anon
        res = [one(t) for t in range(TRIALS)]
        link = statistics.mean(r[0] for r in res)
        pid = statistics.mean(r[1] for r in res)
        anon = statistics.mean(r[2] for r in res)
        print(f"  {n:>8} | {link:>11.3f} | {anon:>9.2f} | {pid:>10.3f} | {1/n:>7.3f}")
    print("  (senders=1 is a single-user node: anon.set collapses to 1, P(sender)=1.0)")

    # -- 4. LATENCY vs MIXING QUALITY tradeoff ------------------------------ #
    hr("4. LATENCY COST vs MIXING QUALITY  (vary batching round window)")
    print(f"  {'round(s)':>9} | {'mean lat':>9} | {'p95 lat':>8} | {'batch sz':>9} | "
          f"{'anon.set':>9} | {'link(both)':>11}")
    for rw in [0.0, 0.5, 1.0, 2.0, 4.0, 8.0, 16.0]:
        def one(t):
            msgs = generate_traffic(N_MSGS, N_SENDERS, N_RECIP, DURATION, seed=3000 + t)
            mode = "both" if rw > 0 else "padding"
            relay = Relay(mode=mode, buckets=SINGLE_BUCKET,
                          round_window=max(rw, 1e-9), seed=8500 + t)
            outs = relay.forward(msgs)
            import collections
            c = collections.Counter(m.out_time for m in outs)
            bsz = statistics.mean(c.values())
            lat = latency_stats(outs)
            anon = mean_anonymity_set(outs)
            link = link_accuracy(msgs, outs, feature="both", seed=9700 + t)
            return lat["mean"], lat["p95"], bsz, anon, link
        res = [one(t) for t in range(TRIALS)]
        cols = [statistics.mean(r[i] for r in res) for i in range(5)]
        print(f"  {rw:>9.1f} | {cols[0]:>9.3f} | {cols[1]:>8.3f} | {cols[2]:>9.1f} | "
              f"{cols[3]:>9.2f} | {cols[4]:>11.3f}")

    print("\nDone.")


if __name__ == "__main__":
    main()
