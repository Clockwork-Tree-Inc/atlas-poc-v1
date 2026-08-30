"""Oblivious PRF hardening (TRUST_LAYER.md #3) — 2HashDH / DH-OPRF, RFC 9497-style.

The recovery server holds a **blind** OPRF key. The client learns `F(k, input)` WITHOUT the
server learning `input`, and without the client learning `k`. This is what kills OFFLINE
brute-force of the low-entropy recovery selector (name+password): whoever steals the ciphertext
store still cannot grind guesses on their own — each guess needs one ONLINE, rate-limited (and
HSM-ed, jurisdiction-sharded) server evaluation. The password stays a SELECTOR, never a key.

PROTOCOL (client ⟷ server):
    blind:    h = H2G(input);  r ← random;  blinded = h^r
    evaluate: (server, per shard)  partial = blinded^{k_i}          # server sees only `blinded`
    combine:  evaluated = ∏ partial = blinded^{Σ k_i} = blinded^k    # additive key sharding
    unblind:  N = evaluated^{r^{-1}} = h^k
    finalize: F = H(input, N)

Additive **key sharding** (`split_key`) puts one share `k_i` on each shard — the real key
`k = Σ k_i` is never assembled anywhere, and evaluation is a product of per-shard partials, so a
shard alone learns nothing and cannot evaluate the PRF by itself. **Proactive refresh**
(`proactive_refresh`, a sharing-of-zero) rotates every share while leaving `k` — and therefore
`F` — unchanged; this is the presence-timed server-share ratchet in miniature (Group E / #15).

REFERENCE NOTE: this uses a 2048-bit MODP **safe-prime** group (RFC 3526 Group 14) with a
hash-to-group by squaring a full-domain hash into the order-`q` subgroup of quadratic residues.
It is a correct, auditable DH-OPRF for the Python **reference-of-record**. A production build uses
RFC 9497 over ristretto255 / P-256 with proper hash-to-curve; the protocol and its security
argument are identical. This is a **server-side** primitive (HSM + shards); the iOS client would
use a vetted EC-OPRF binding, not a hand-rolled 2048-bit modexp — so there is no Swift mirror
(same posture as `realid/recovery_anchor`).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence

from ..crypto.primitives import H, random_bytes

# RFC 3526 Group 14 — a 2048-bit MODP safe prime (p = 2q + 1, q prime).
_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
_Q = (_P - 1) // 2                    # order of the quadratic-residue subgroup
_ELEM_BYTES = (_P.bit_length() + 7) // 8


class OPRFError(Exception):
    pass


def _i2osp(x: int) -> bytes:
    return x.to_bytes(_ELEM_BYTES, "big")


def _random_scalar() -> int:
    """A uniform-ish nonzero scalar in [1, Q). Reject 0."""
    while True:
        s = int.from_bytes(random_bytes(_ELEM_BYTES + 16), "big") % _Q  # extra bytes reduce bias
        if s != 0:
            return s


def _fdh(data: bytes) -> int:
    """Full-domain hash of `data` into [0, P): expand H past P's bit length to limit bias."""
    out = bytearray()
    i = 0
    while len(out) * 8 < _P.bit_length() + 128:
        out += H(b"atlas/oprf-fdh", i.to_bytes(4, "big"), data)
        i += 1
    return int.from_bytes(bytes(out), "big") % _P


def _in_subgroup(x: int) -> bool:
    """Is `x` a genuine element of the prime-order-q subgroup? Rejects the identity, out-of-range
    values, and small-subgroup elements (e.g. the order-2 element P-1). Without this check a
    malicious party can submit P-1 and learn the parity of a key share per query — the classic
    small-subgroup leak; RFC 9497 mandates this validation."""
    return 1 < x < _P and pow(x, _Q, _P) == 1


def hash_to_group(data: bytes) -> int:
    """Map `data` to an element of the order-q QR subgroup (square the full-domain hash)."""
    h = pow(_fdh(data), 2, _P)
    if h in (0, 1):                    # astronomically unlikely; fail closed
        raise OPRFError("degenerate hash-to-group element")
    return h


# --------------------------------------------------------------------------- key material
def keygen() -> int:
    """A fresh OPRF key `k` in [1, Q)."""
    return _random_scalar()


def split_key(k: int, n: int) -> List[int]:
    """Additive n-of-n sharding of `k` mod Q: shares sum to k, none reveals k. Each goes on a
    separate shard (jurisdiction). NOTE this is n-of-n (every shard participates) — the point is
    no single operator can evaluate the PRF; k-of-n availability is a separate deployment layer."""
    if n < 1:
        raise OPRFError("need at least one shard")
    shares = [_random_scalar() for _ in range(n - 1)]
    last = (k - sum(shares)) % _Q
    shares.append(last)
    return shares


def proactive_refresh(shares: Sequence[int]) -> List[int]:
    """Rotate every share by a fresh sharing-of-zero. The sum (the real key `k`) is unchanged,
    so `F` is identical; only the shares rotate — defeating a roving adversary that compromises
    one shard at a time. This is the server-share proactive ratchet (Group E / #15) in miniature."""
    n = len(shares)
    if n < 1:
        raise OPRFError("no shares to refresh")
    zero = [_random_scalar() for _ in range(n - 1)]
    zero.append((-sum(zero)) % _Q)     # the n deltas sum to 0 mod Q
    return [(s + d) % _Q for s, d in zip(shares, zero)]


# --------------------------------------------------------------------------- shard (server)
@dataclass(frozen=True)
class OPRFShard:
    """One server shard holding a single key share. Sees only the blinded element; learns
    nothing about the client input and cannot evaluate the PRF alone."""

    key_share: int

    def evaluate(self, blinded: int) -> int:
        if not _in_subgroup(blinded):
            raise OPRFError("blinded element is not in the prime-order subgroup")
        return pow(blinded, self.key_share % _Q, _P)


# --------------------------------------------------------------------------- client
def blind(input_bytes: bytes) -> tuple[int, int]:
    """Blind `input_bytes` for oblivious evaluation. Returns `(blinded, r)`; keep `r` secret."""
    h = hash_to_group(input_bytes)
    r = _random_scalar()
    return pow(h, r, _P), r


def combine_partials(partials: Sequence[int]) -> int:
    """Combine per-shard partial evaluations: ∏ blinded^{k_i} = blinded^{Σ k_i}."""
    if not partials:
        raise OPRFError("no partial evaluations to combine")
    acc = 1
    for pe in partials:
        if not _in_subgroup(pe):
            raise OPRFError("partial evaluation is not in the prime-order subgroup")
        acc = (acc * pe) % _P
    return acc


def unblind(evaluated: int, r: int) -> int:
    """Remove the blind: evaluated^{r^{-1}} = h^k."""
    r_inv = pow(r % _Q, -1, _Q)
    return pow(evaluated, r_inv, _P)


def finalize(input_bytes: bytes, unblinded: int) -> bytes:
    """The PRF output F(k, input) = H(input, h^k)."""
    return H(b"atlas/oprf-finalize", input_bytes, _i2osp(unblinded))


def evaluate_oblivious(shards: Sequence[OPRFShard], input_bytes: bytes) -> bytes:
    """Full client run against a set of shards: blind → per-shard evaluate → combine → unblind →
    finalize. The shards jointly compute F without learning `input`; the client never sees any
    key share. Independent of the (secret) blind `r`, so it is a deterministic PRF of the input."""
    blinded, r = blind(input_bytes)
    partials = [s.evaluate(blinded) for s in shards]
    return finalize(input_bytes, unblind(combine_partials(partials), r))


def evaluate_full(k: int, input_bytes: bytes) -> bytes:
    """Non-oblivious oracle F(k, input) — for tests / a trusted single evaluator: H(input, h^k)."""
    return finalize(input_bytes, pow(hash_to_group(input_bytes), k % _Q, _P))
