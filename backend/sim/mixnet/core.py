"""
Pure-Python reference simulation of a content-blind mix relay.

Models synthetic traffic (senders -> recipients through a single relay) and
four protection modes:

    (a) NONE     - forward each message unchanged
    (b) PADDING  - normalize message size into fixed buckets
    (c) BATCHING - collect messages for a round window, release shuffled
    (d) BOTH     - padding + batching

An OBSERVER sits on the wire. It sees INPUT events (into the relay) and OUTPUT
events (out of the relay). The relay forwards exactly one output per input, so a
ground-truth 1:1 pairing exists. The observer tries to reconstruct that pairing
(input->output linking) and, separately, to identify the SENDER behind an output
message (anonymity-set attack).

Only Python stdlib is used. `secrets`/`random` are fine here: this is a
measurement harness, not the Atlas workflow engine.
"""

from __future__ import annotations

import math
import random
import statistics
from dataclasses import dataclass, field
from typing import Callable, Optional


# --------------------------------------------------------------------------- #
# Traffic model
# --------------------------------------------------------------------------- #

@dataclass
class Message:
    mid: int              # unique id, also the ground-truth link label
    sender: int
    recipient: int
    size: int             # bytes, as it enters the relay
    send_time: float      # seconds, when it enters the relay

    # filled in by the relay when it forwards:
    out_size: Optional[int] = None
    out_time: Optional[float] = None
    out_order: Optional[int] = None   # index in the observed output stream


def lognormal_size(rng: random.Random, mu: float = 7.0, sigma: float = 1.2,
                   lo: int = 64, hi: int = 1_000_000) -> int:
    """Realistic, highly-varied message sizes (bytes). Distinct-ish values so
    that size is a strong linking feature when left unprotected."""
    v = int(math.exp(rng.gauss(mu, sigma)))
    return max(lo, min(hi, v))


def generate_traffic(num_messages: int,
                     num_senders: int,
                     num_recipients: int,
                     duration: float = 60.0,
                     seed: Optional[int] = None) -> list[Message]:
    """Poisson-ish arrivals over `duration` seconds. Each message picks a random
    sender, recipient and a lognormal size."""
    rng = random.Random(seed)
    msgs = []
    for i in range(num_messages):
        msgs.append(Message(
            mid=i,
            sender=rng.randrange(num_senders),
            recipient=rng.randrange(num_recipients),
            size=lognormal_size(rng),
            send_time=rng.uniform(0.0, duration),
        ))
    msgs.sort(key=lambda m: m.send_time)
    return msgs


# --------------------------------------------------------------------------- #
# Relay (the content-blind node)
# --------------------------------------------------------------------------- #

# Fixed size buckets for padding (bytes). A message is padded UP to the next
# bucket. Coarser buckets => more messages collide => less size leakage.
DEFAULT_BUCKETS = [1024, 4096, 16384, 65536, 262144, 1048576]
SINGLE_BUCKET = [1048576]   # normalize everything to one size (max leakage kill)


def pad_to_bucket(size: int, buckets: list[int]) -> int:
    for b in buckets:
        if size <= b:
            return b
    return buckets[-1]


@dataclass
class Relay:
    mode: str = "none"                 # none | padding | batching | both
    buckets: list[int] = field(default_factory=lambda: DEFAULT_BUCKETS)
    round_window: float = 1.0          # seconds, batch collection window
    proc_delay: float = 0.01           # forwarding delay in non-batched modes
    seed: Optional[int] = None

    def forward(self, msgs: list[Message]) -> list[Message]:
        rng = random.Random(self.seed)
        pad = self.mode in ("padding", "both")
        batch = self.mode in ("batching", "both")

        out_stream: list[Message] = []

        if not batch:
            # Order-preserving forward with a tiny per-hop delay.
            for m in sorted(msgs, key=lambda x: x.send_time):
                m.out_size = pad_to_bucket(m.size, self.buckets) if pad else m.size
                m.out_time = m.send_time + self.proc_delay
                out_stream.append(m)
            out_stream.sort(key=lambda x: x.out_time)
        else:
            # Collect into fixed round windows; release each round shuffled with
            # a single shared release timestamp so within-batch timing is flat.
            msgs_sorted = sorted(msgs, key=lambda x: x.send_time)
            if not msgs_sorted:
                return []
            round_of: dict[int, list[Message]] = {}
            for m in msgs_sorted:
                r = int(m.send_time // self.round_window)
                round_of.setdefault(r, []).append(m)
            for r in sorted(round_of):
                release_time = (r + 1) * self.round_window
                group = round_of[r][:]
                rng.shuffle(group)                     # destroy input order
                for m in group:
                    m.out_size = pad_to_bucket(m.size, self.buckets) if pad else m.size
                    m.out_time = release_time           # flat timestamp
                    out_stream.append(m)

        for idx, m in enumerate(out_stream):
            m.out_order = idx
        return out_stream


# --------------------------------------------------------------------------- #
# Observer (the adversary on the wire)
# --------------------------------------------------------------------------- #

def _greedy_assign(inputs: list[Message],
                   outputs: list[Message],
                   dist: Callable[[Message, Message], float],
                   rng: random.Random) -> dict[int, int]:
    """Greedy min-distance 1:1 assignment input.mid -> output.mid.
    Ties are broken randomly so that a fully-uninformative feature yields a
    uniformly random permutation (expected accuracy = 1/N, i.e. pure chance)."""
    pairs = []
    for a in inputs:
        for b in outputs:
            # random jitter << any real distance gap, only to break exact ties
            pairs.append((dist(a, b), rng.random(), a.mid, b.mid))
    pairs.sort()
    assigned_in: set[int] = set()
    assigned_out: set[int] = set()
    result: dict[int, int] = {}
    for _d, _j, a_mid, b_mid in pairs:
        if a_mid in assigned_in or b_mid in assigned_out:
            continue
        result[a_mid] = b_mid
        assigned_in.add(a_mid)
        assigned_out.add(b_mid)
    return result


def link_accuracy(inputs: list[Message],
                  outputs: list[Message],
                  feature: str,
                  seed: Optional[int] = None) -> float:
    """Fraction of input messages the observer links to their true output.

    feature:
      'size'  - use only the (possibly padded) size
      'time'  - use only output timing/order
      'both'  - use size and timing combined
    """
    rng = random.Random(seed)

    # Normalizers for combining features on a comparable scale.
    in_sizes = [m.size for m in inputs]
    size_scale = (max(in_sizes) - min(in_sizes)) or 1.0

    def d_size(a: Message, b: Message) -> float:
        return abs(a.size - b.out_size) / size_scale

    def d_time(a: Message, b: Message) -> float:
        # observer expects output shortly after input; batching flattens times
        return abs((b.out_time - a.send_time))

    if feature == "size":
        dist = d_size
    elif feature == "time":
        dist = d_time
    elif feature == "both":
        dist = lambda a, b: d_size(a, b) + d_time(a, b)
    else:
        raise ValueError(feature)

    assign = _greedy_assign(inputs, outputs, dist, rng)
    correct = sum(1 for m in inputs if assign.get(m.mid) == m.mid)
    return correct / len(inputs)


def sender_identification(outputs: list[Message]) -> float:
    """Anonymity-set attack. For each output message the observer knows the set
    of senders whose traffic *could* be in that batch (the crowd it was mixed
    with) and guesses uniformly among them. Returns mean P(correct sender).

    With a single-user node every batch contains one sender -> P = 1.0.
    With a federation of N active senders per batch -> P ~ 1/N.
    """
    # Group outputs by their release timestamp = the batch they were mixed in.
    batches: dict[float, list[Message]] = {}
    for m in outputs:
        batches.setdefault(m.out_time, []).append(m)
    probs = []
    for group in batches.values():
        crowd = len(set(m.sender for m in group))   # distinct senders in batch
        probs.append(1.0 / crowd)
    return statistics.mean(probs) if probs else 1.0


def mean_anonymity_set(outputs: list[Message]) -> float:
    """Mean number of distinct senders mixed together per batch (the crowd)."""
    batches: dict[float, list[Message]] = {}
    for m in outputs:
        batches.setdefault(m.out_time, []).append(m)
    if not batches:
        return 1.0
    return statistics.mean(len(set(m.sender for m in g)) for g in batches.values())


def latency_stats(outputs: list[Message]) -> dict[str, float]:
    lat = [m.out_time - m.send_time for m in outputs]
    return {
        "mean": statistics.mean(lat),
        "p50": statistics.median(lat),
        "p95": sorted(lat)[int(0.95 * (len(lat) - 1))],
        "max": max(lat),
    }
