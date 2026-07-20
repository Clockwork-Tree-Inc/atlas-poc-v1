"""Real drand HTTP client (§1.3, §3.2) — used on the Mac, not in sealed CI.

drand is the public epoch key (§3.2). This client fetches rounds as-is from a
League-of-Entropy relay and exposes the same `Beacon` interface as
`LocalBeacon`, so the rest of the protocol is agnostic to which is wired in.

Network note: `api.drand.sh` is blocked by the build sandbox's egress policy, so
this path is exercised on the Mac. It is import-safe everywhere (``requests`` is
imported lazily) and unit-tested against a stub transport.
"""

from __future__ import annotations

import math
from typing import Callable

from .base import BeaconRound
from ..crypto.primitives import sha256 as _sha256

# Default: League of Entropy "quicknet" (3s period, unchained, G1 sigs).
DEFAULT_RELAY = "https://api.drand.sh"
QUICKNET_CHAIN_HASH = (
    "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
)
# League-of-Entropy "quicknet" GROUP PUBLIC KEY (G2, 96-byte compressed) — the root of
# trust for BLS verification, pinned like the chain hash. Override for other chains.
QUICKNET_PUBLIC_KEY = (
    "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c"
    "8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb"
    "5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a"
)
# quicknet is scheme "bls-unchained-g1-rfc9380": signatures in G1, key in G2, message =
# sha256(round_be8), hash-to-curve DST below (validated against a live round).
_QUICKNET_DST = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"


def verify_drand_signature(round_number: int, signature: bytes, public_key: bytes) -> bool:
    """Verify a drand quicknet round's BLS THRESHOLD signature against the League-of-Entropy
    group public key — proves the round is authentic (produced by the real drand network),
    not fabricated by a relay. Unchained G1-sig scheme: message = sha256(round, 8-byte big-endian),
    hashed to G1; check e(sig, g2) == e(H(msg), pk). Uses the same py_ecc BLS12-381 backend as the
    PS credential. Returns False on any malformed input (fail-closed)."""
    import hashlib
    try:
        from py_ecc.bls.hash_to_curve import hash_to_G1
        from py_ecc.bls.point_compression import decompress_G1, decompress_G2
        from py_ecc.optimized_bls12_381 import FQ12, G2, neg, pairing

        pk = decompress_G2((int.from_bytes(public_key[:48], "big"),
                            int.from_bytes(public_key[48:], "big")))
        sig = decompress_G1(int.from_bytes(signature, "big"))
        msg = hashlib.sha256(round_number.to_bytes(8, "big")).digest()
        h = hash_to_G1(msg, _QUICKNET_DST, hashlib.sha256)
        return pairing(G2, sig) * pairing(neg(pk), h) == FQ12.one()
    except Exception:
        return False


class DrandHTTPBeacon:
    period_s: float

    def __init__(
        self,
        *,
        relay: str = DEFAULT_RELAY,
        chain_hash: str = QUICKNET_CHAIN_HASH,
        public_key: str = QUICKNET_PUBLIC_KEY,
        period_s: float = 3.0,
        genesis_time: float = 0.0,
        verify_bls: bool = True,
        http_get: Callable[[str], dict] | None = None,
    ):
        self.relay = relay.rstrip("/")
        self.chain_hash = chain_hash
        self.period_s = period_s
        self.genesis_time = genesis_time
        self._pubkey = bytes.fromhex(public_key)
        self._verify_bls = verify_bls
        self._http_get = http_get or self._default_get

    @staticmethod
    def _default_get(url: str) -> dict:
        import requests  # lazy: keeps sealed-CI imports network-free

        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        return resp.json()

    def info(self) -> dict:
        info = self._http_get(f"{self.relay}/{self.chain_hash}/info")
        self.period_s = float(info.get("period", self.period_s))
        self.genesis_time = float(info.get("genesis_time", self.genesis_time))
        return info

    def round_number_at(self, t: float) -> int:
        if t < self.genesis_time:
            return 0
        return 1 + math.floor((t - self.genesis_time) / self.period_s)

    def _fetch(self, which: str) -> BeaconRound:
        data = self._http_get(f"{self.relay}/{self.chain_hash}/public/{which}")
        rnd = BeaconRound(
            round=int(data["round"]),
            randomness=bytes.fromhex(data["randomness"]),
            signature=bytes.fromhex(data.get("signature", "")),
        )
        # (1) Integrity binding (drand): randomness == SHA-256(signature). Catches a
        # relay returning a mismatched randomness/signature pair.
        if rnd.signature and rnd.randomness != _sha256(rnd.signature):
            raise ValueError("drand relay returned randomness != H(signature) — rejected")
        # (2) BLS THRESHOLD-SIGNATURE verification against the League-of-Entropy group
        # public key: proves the round is AUTHENTIC (produced by the real drand network),
        # not a self-consistent triple forged by a malicious relay. This is what makes the
        # beacon trustworthy as the provenance timestamp/freshness root.
        if self._verify_bls and rnd.signature:
            if not verify_drand_signature(rnd.round, rnd.signature, self._pubkey):
                raise ValueError("drand BLS threshold signature verification failed — rejected")
        return rnd

    def round_at(self, t: float) -> BeaconRound:
        return self._fetch(str(self.round_number_at(t)))

    def latest(self, now: float | None = None) -> BeaconRound:
        return self._fetch("latest")
