"""
Federation of mixing relays + cover traffic -- closing the ANONYMITY-SET gap.

Background (see core.py + run_measurements.py):
    A SINGLE content-blind relay can normalize traffic SHAPE (padding kills the
    size channel, batching kills the timing channel) but if that relay is a
    single self-owned node then every batch contains exactly one sender: the
    anonymity set is 1 and sender identification is 100%. Shape privacy without
    an anonymity set is not sender privacy.

This module closes that gap by simulating the two missing ingredients:

    1. A FEDERATION of independent relays. A message is onion-routed across
       H independent relays (a Chaum mix cascade). Each relay batches and
       shuffles traffic from MANY independent senders, and -- crucially --
       each relay only sees its immediate predecessor and successor on the
       path, never both true endpoints of a message. The anonymity set is the
       crowd a message is mixed with, and it grows across hops.

    2. COVER TRAFFIC. Each user emits a constant-rate stream of packets
       (real messages displace dummies inside a fixed budget), so the mere
       fact that a user is ACTIVE is hidden from a link observer.

An OBSERVER on the wire tries to (a) name the sender of a target message by
tracing the mix cascade backward, and (b) decide whether a given user is active
from the packet pattern on that user's access link.

Only Python stdlib is used. Reuses core.py for traffic generation, size padding
and latency stats.

Run:
    python -m sim.mixnet.federation      (from backend/, with '.' on path)
"""

from __future__ import annotations

import collections
import math
import random
import statistics
from dataclasses import dataclass, field
from typing import Optional

from sim.mixnet.core import (
    generate_traffic, pad_to_bucket, latency_stats, SINGLE_BUCKET,
)


# --------------------------------------------------------------------------- #
# Node identities on the wire.
#   ("S", i) = sender/user endpoint      ("R", i) = relay      ("D", i) = recipient
# The observer can read these off the links (who talks to whom), but onion
# layers hide everything past the immediate neighbour.
# --------------------------------------------------------------------------- #

def S(i): return ("S", i)
def R(i): return ("R", i)
def D(i): return ("D", i)


@dataclass
class HopRecord:
    relay: int
    hop_index: int          # 0 .. H-1
    in_time: float
    out_time: float
    out_round: int
    prev_node: tuple        # what THIS relay sees as the previous node
    next_node: tuple        # what THIS relay sees as the next node
    batch_key: tuple        # (relay, out_round) -- the mix this packet sat in


@dataclass
class Packet:
    pid: int
    sender: int
    recipient: int
    size: int
    send_time: float
    is_dummy: bool = False
    path: list[int] = field(default_factory=list)     # relay ids, length H
    hops: list[HopRecord] = field(default_factory=list)
    out_size: Optional[int] = None
    deliver_time: Optional[float] = None


# --------------------------------------------------------------------------- #
# Federation: H-hop onion mix cascade over `num_relays` independent relays.
# --------------------------------------------------------------------------- #

@dataclass
class Federation:
    num_relays: int = 5
    hops: int = 3                      # H: independent relays on each path
    round_window: float = 1.0          # batching window per relay (seconds)
    buckets: list[int] = field(default_factory=lambda: list(SINGLE_BUCKET))
    seed: Optional[int] = None

    # ---- routing ---------------------------------------------------------- #
    def _pick_path(self, rng: random.Random) -> list[int]:
        """A path of H DISTINCT relays (so the first and last hop are never the
        same node -- a precondition for 'no single relay sees both ends')."""
        H = min(self.hops, self.num_relays)
        return rng.sample(range(self.num_relays), H)

    # ---- simulation ------------------------------------------------------- #
    def route(self, packets: list[Packet]) -> dict:
        """Onion-route every packet across its H-hop path. Each relay batches
        packets that arrive in the same round window and releases them together
        with a single flat timestamp (order + timing destroyed within a batch).

        Returns a state dict with per-packet hop records and a batch index
        {batch_key -> set(pid)} used by the backward-tracing observer.
        """
        rng = random.Random(self.seed)
        by_pid = {p.pid: p for p in packets}

        # assign paths
        for p in packets:
            if not p.path:
                p.path = self._pick_path(rng)

        # Onion forwarding, hop by hop, with per-relay round batching.
        batches: dict[tuple, set] = collections.defaultdict(set)
        for p in packets:
            t = p.send_time
            prev = S(p.sender)
            p.out_size = pad_to_bucket(p.size, self.buckets)
            p.hops = []
            H = len(p.path)
            for h, relay in enumerate(p.path):
                in_time = t
                rnd = int(in_time // self.round_window)
                out_time = (rnd + 1) * self.round_window
                nxt = R(p.path[h + 1]) if (h + 1) < H else D(p.recipient)
                bk = (relay, rnd)
                p.hops.append(HopRecord(
                    relay=relay, hop_index=h, in_time=in_time, out_time=out_time,
                    out_round=rnd, prev_node=prev, next_node=nxt, batch_key=bk,
                ))
                batches[bk].add(p.pid)
                t = out_time
                prev = R(relay)
            p.deliver_time = t

        return {"packets": packets, "by_pid": by_pid, "batches": batches,
                "hops": self.hops}


# --------------------------------------------------------------------------- #
# OBSERVER (a): sender identification by backward-tracing the mix cascade.
# --------------------------------------------------------------------------- #

def anonymity_set(state: dict, target_pid: int) -> set:
    """The set of ORIGINAL SENDERS the observer cannot rule out for the target.

    The observer sees the target leave the last relay in a batch of K messages
    -> the target is any one of those K. Each of those K entered the last relay
    from a previous-hop batch -> undo that mix too -> union. Repeated back to
    hop 0, the reachable original senders are the anonymity set. (For H=1 this
    reduces to 'distinct senders in the single batch', matching core.py.)
    """
    by_pid = state["by_pid"]
    batches = state["batches"]
    tgt = by_pid[target_pid]
    H = len(tgt.hops)

    # candidates for "which packet is the target", starting at the LAST mix
    cand = set(batches[tgt.hops[H - 1].batch_key])
    # undo earlier hops, unioning in each candidate's batch at that hop
    for h in range(H - 2, -1, -1):
        nxt = set()
        for c in cand:
            nxt |= batches[by_pid[c].hops[h].batch_key]
        cand = nxt

    return {by_pid[c].sender for c in cand if not by_pid[c].is_dummy}


def sender_identification(state: dict, real_only: bool = True) -> float:
    """Mean P(observer names the true sender) over real target messages,
    guessing uniformly inside the anonymity set: mean of 1/|anon set|."""
    packets = state["packets"]
    probs = []
    for p in packets:
        if real_only and p.is_dummy:
            continue
        a = anonymity_set(state, p.pid)
        # the true sender is always in its own anon set, so |a| >= 1
        probs.append(1.0 / max(1, len(a)))
    return statistics.mean(probs) if probs else 1.0


def mean_anonymity_set(state: dict, real_only: bool = True) -> float:
    packets = state["packets"]
    sizes = []
    for p in packets:
        if real_only and p.is_dummy:
            continue
        sizes.append(len(anonymity_set(state, p.pid)))
    return statistics.mean(sizes) if sizes else 1.0


# --------------------------------------------------------------------------- #
# OBSERVER (b): does ANY single relay see both true endpoints of a message?
# --------------------------------------------------------------------------- #

def both_ends_violations(state: dict) -> int:
    """Count (relay, message) pairs where one relay observes BOTH a true sender
    endpoint as predecessor AND a true recipient endpoint as successor -- i.e.
    that relay alone links sender<->recipient. Must be 0 when H>=2."""
    v = 0
    for p in state["packets"]:
        for hop in p.hops:
            if hop.prev_node[0] == "S" and hop.next_node[0] == "D":
                v += 1
    return v


def relay_endpoint_view(state: dict) -> dict:
    """For reporting: per relay, how many messages it saw the sender of, the
    recipient of, and both."""
    view = collections.defaultdict(lambda: {"sender": 0, "recipient": 0, "both": 0})
    for p in state["packets"]:
        for hop in p.hops:
            sees_s = hop.prev_node[0] == "S"
            sees_d = hop.next_node[0] == "D"
            if sees_s:
                view[hop.relay]["sender"] += 1
            if sees_d:
                view[hop.relay]["recipient"] += 1
            if sees_s and sees_d:
                view[hop.relay]["both"] += 1
    return dict(view)


# --------------------------------------------------------------------------- #
# COVER TRAFFIC + OBSERVER (c): can a link observer tell active from idle?
# --------------------------------------------------------------------------- #

def _poisson(rng: random.Random, lam: float) -> int:
    """Knuth's algorithm. lam small enough here for it to be fine."""
    if lam <= 0:
        return 0
    L = math.exp(-lam)
    k, pr = 0, 1.0
    while True:
        k += 1
        pr *= rng.random()
        if pr <= L:
            return k - 1


def _observed_count(real: int, cover_rate: float, rng: random.Random) -> int:
    """Packets an observer counts on a user's access link in one window.

    cover_rate <= 0  : no cover -- only real messages appear on the wire.
    cover_rate  > 0  : CONSTANT-RATE cover. The channel draws a per-window
                       dummy budget ~Poisson(cover_rate); real messages DISPLACE
                       dummies inside that budget, so the emitted count is
                       max(real, budget). When the budget covers the real load,
                       an active user's link looks identical to an idle one's.
    """
    if cover_rate <= 0:
        return real
    budget = _poisson(rng, cover_rate)
    return max(real, budget)


def activity_detection_accuracy(cover_rate: float,
                                mu_active: float = 8.0,
                                mu_idle: float = 0.0,
                                trials: int = 20000,
                                seed: int = 0) -> float:
    """2AFC: the observer is shown one ACTIVE-window trace and one IDLE-window
    trace (which is which is hidden) and must point at the active one, using the
    packet count on the access link. Returns accuracy in [0,1]; 0.5 = pure
    chance (the observer learns nothing about activity)."""
    rng = random.Random(seed)
    correct = 0.0
    for _ in range(trials):
        a_real = _poisson(rng, mu_active)
        i_real = _poisson(rng, mu_idle)
        a_obs = _observed_count(a_real, cover_rate, rng)
        i_obs = _observed_count(i_real, cover_rate, rng)
        if a_obs > i_obs:
            correct += 1.0
        elif a_obs == i_obs:
            correct += 0.5           # indistinguishable -> forced coin flip
    return correct / trials


# --------------------------------------------------------------------------- #
# Convenience builders
# --------------------------------------------------------------------------- #

def build_real_packets(num_messages: int, num_senders: int, num_recipients: int,
                       duration: float, seed: int) -> list[Packet]:
    msgs = generate_traffic(num_messages, num_senders, num_recipients, duration, seed=seed)
    return [Packet(pid=m.mid, sender=m.sender, recipient=m.recipient,
                   size=m.size, send_time=m.send_time) for m in msgs]


def add_cover_packets(packets: list[Packet], num_senders: int, num_recipients: int,
                      duration: float, cover_per_sender: float, seed: int) -> list[Packet]:
    """Append dummy packets so senders emit a steady stream. Dummies are onion
    packets indistinguishable from real ones once padded; they enlarge every
    batch's crowd and are what a constant-rate access link actually transmits."""
    rng = random.Random(seed)
    nxt = max((p.pid for p in packets), default=-1) + 1
    out = list(packets)
    total_dummies = int(cover_per_sender * num_senders)
    for _ in range(total_dummies):
        out.append(Packet(
            pid=nxt, sender=rng.randrange(num_senders),
            recipient=rng.randrange(num_recipients),
            size=rng.randint(64, 1024), send_time=rng.uniform(0.0, duration),
            is_dummy=True,
        ))
        nxt += 1
    out.sort(key=lambda p: p.send_time)
    return out


# --------------------------------------------------------------------------- #
# Measurement report
# --------------------------------------------------------------------------- #

TRIALS = 8
N_MSGS = 600
N_SENDERS = 20
N_RECIP = 20
DURATION = 60.0
ROUND = 1.0
NUM_RELAYS = 5


def _hr(title):
    print("\n" + "=" * 74)
    print(title)
    print("=" * 74)


def _avg(fn, trials=TRIALS):
    vals = [fn(t) for t in range(trials)]
    return statistics.mean(vals), (statistics.pstdev(vals) if len(vals) > 1 else 0.0)


def main():
    print(f"Config: {N_MSGS} msgs, {N_SENDERS} senders, {N_RECIP} recipients, "
          f"{NUM_RELAYS} relays, round={ROUND:.1f}s, {DURATION:.0f}s, {TRIALS} trials")

    # ---- 1. ANONYMITY SET: single node vs federation, and vs hops --------- #
    _hr("1. ANONYMITY SET  (padding+batching ON; can the observer name the sender?)")
    print("  baseline: a SINGLE self-owned node (1 sender, 1 hop)")
    def base(t):
        pk = build_real_packets(N_MSGS, 1, N_RECIP, DURATION, seed=100 + t)
        st = Federation(num_relays=1, hops=1, round_window=ROUND, seed=700 + t).route(pk)
        return sender_identification(st), mean_anonymity_set(st)
    bp, ba = zip(*[base(t) for t in range(TRIALS)])
    print(f"    senders=1, H=1  ->  anon.set = {statistics.mean(ba):.2f}   "
          f"P(sender) = {statistics.mean(bp):.3f}   (this is the gap: 100% id)")

    print(f"\n  federation: {N_SENDERS} independent senders, vary hops H")
    print(f"    {'H hops':>7} | {'anon.set':>9} | {'P(sender)':>10} | {'1/N':>6}")
    anon_by_H = {}
    for H in [1, 2, 3]:
        def one(t):
            pk = build_real_packets(N_MSGS, N_SENDERS, N_RECIP, DURATION, seed=200 + t)
            st = Federation(num_relays=NUM_RELAYS, hops=H, round_window=ROUND,
                            seed=800 + t).route(pk)
            return sender_identification(st), mean_anonymity_set(st)
        res = [one(t) for t in range(TRIALS)]
        pid = statistics.mean(r[0] for r in res)
        anon = statistics.mean(r[1] for r in res)
        anon_by_H[H] = (pid, anon)
        print(f"    {H:>7} | {anon:>9.2f} | {pid:>10.3f} | {1/N_SENDERS:>6.3f}")
    print(f"  -> more hops union more crowds: the anonymity set grows toward N={N_SENDERS},")
    print(f"     P(sender) falls from 1.0 (single node) toward 1/N = {1/N_SENDERS:.3f}.")

    print(f"\n  scaling senders N at H=3 (federation):")
    print(f"    {'senders':>8} | {'anon.set':>9} | {'P(sender)':>10} | {'1/N':>6}")
    for n in [1, 2, 5, 10, 20, 50]:
        def one(t):
            pk = build_real_packets(N_MSGS, n, N_RECIP, DURATION, seed=300 + t)
            st = Federation(num_relays=NUM_RELAYS, hops=3, round_window=ROUND,
                            seed=900 + t).route(pk)
            return sender_identification(st), mean_anonymity_set(st)
        res = [one(t) for t in range(TRIALS)]
        pid = statistics.mean(r[0] for r in res)
        anon = statistics.mean(r[1] for r in res)
        print(f"    {n:>8} | {anon:>9.2f} | {pid:>10.3f} | {1/n:>6.3f}")

    # ---- 2. NO SINGLE RELAY SEES BOTH ENDS -------------------------------- #
    _hr("2. NO SINGLE POINT SEES BOTH ENDS  (per-relay endpoint view)")
    for H in [1, 2, 3]:
        def one(t):
            pk = build_real_packets(N_MSGS, N_SENDERS, N_RECIP, DURATION, seed=400 + t)
            st = Federation(num_relays=NUM_RELAYS, hops=H, round_window=ROUND,
                            seed=1000 + t).route(pk)
            return both_ends_violations(st)
        v, _ = _avg(one)
        verdict = "SEES BOTH ENDS (no protection)" if v > 0 else "no relay links sender<->recipient"
        print(f"    H={H}: single-relay (sender AND recipient) observations = {v:.0f}   -> {verdict}")
    # show a per-relay breakdown for H=3
    pk = build_real_packets(N_MSGS, N_SENDERS, N_RECIP, DURATION, seed=42)
    st = Federation(num_relays=NUM_RELAYS, hops=3, round_window=ROUND, seed=42).route(pk)
    view = relay_endpoint_view(st)
    print(f"\n    per-relay view at H=3 (msgs whose sender / recipient / BOTH it saw):")
    for r in sorted(view):
        vv = view[r]
        print(f"      relay {r}: sender={vv['sender']:>4}  recipient={vv['recipient']:>4}  both={vv['both']:>4}")

    # ---- 3. COVER TRAFFIC closes activity-timing -------------------------- #
    _hr("3. COVER TRAFFIC  (can a link observer tell 'user active' from 'idle'?)")
    print("    2AFC accuracy: 1.0 = observer always right, 0.5 = pure chance")
    print(f"    {'cover rate':>11} | {'detect acc':>10} | {'advantage':>10}")
    for cr in [0.0, 2.0, 4.0, 8.0, 16.0, 32.0]:
        acc = activity_detection_accuracy(cr, mu_active=8.0, mu_idle=0.0,
                                          trials=40000, seed=7)
        print(f"    {cr:>11.1f} | {acc:>10.3f} | {acc - 0.5:>+10.3f}")
    print("    -> with no cover an active link is obvious (acc ~ 1.0); a constant-rate")
    print("       cover budget >= the real load collapses detection to chance (~0.5).")

    # ---- 4. COST: bandwidth + latency ------------------------------------- #
    _hr("4. COST OF THE ANONYMITY SET  (bandwidth + latency -- the price)")
    # latency = H hops x round window, measured
    print(f"    {'H hops':>7} | {'mean lat':>9} | {'p95 lat':>8} | {'relay-bw x':>11}")
    for H in [1, 2, 3]:
        def one(t):
            pk = build_real_packets(N_MSGS, N_SENDERS, N_RECIP, DURATION, seed=500 + t)
            st = Federation(num_relays=NUM_RELAYS, hops=H, round_window=ROUND,
                            seed=1100 + t).route(pk)
            lat = [p.deliver_time - p.send_time for p in st["packets"]]
            return statistics.mean(lat), sorted(lat)[int(0.95 * (len(lat) - 1))]
        res = [one(t) for t in range(TRIALS)]
        ml = statistics.mean(r[0] for r in res)
        p95 = statistics.mean(r[1] for r in res)
        # relay-bandwidth multiplier: each message crosses H links instead of 1
        print(f"    {H:>7} | {ml:>9.3f} | {p95:>8.3f} | {float(H):>10.1f}x")
    # cover-traffic bandwidth overhead
    print(f"\n    cover-traffic bandwidth overhead (total emitted / real payload):")
    print(f"    {'cover/sender':>13} | {'total pkts':>10} | {'overhead x':>11}")
    for cps in [0.0, 5.0, 10.0, 20.0]:
        pk = build_real_packets(N_MSGS, N_SENDERS, N_RECIP, DURATION, seed=55)
        allp = add_cover_packets(pk, N_SENDERS, N_RECIP, DURATION, cps, seed=55)
        overhead = len(allp) / len(pk)
        print(f"    {cps:>13.1f} | {len(allp):>10} | {overhead:>10.2f}x")
    print("    -> the price of the anonymity set is H x relay bandwidth, ~H x round-window")
    print("       latency, and a constant multiple of cover bandwidth. That is the trade.")

    print("\nDone.")


if __name__ == "__main__":
    main()
