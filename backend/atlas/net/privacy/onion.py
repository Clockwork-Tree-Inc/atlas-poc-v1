"""Sphinx-style onion packets over the hybrid PQ KEM — the core of the Tier-2 mixnet backend (#51).

A message is wrapped in one encryption LAYER per hop. Each hop peels exactly one layer with its own
KEM key and learns ONLY the next hop's id and the still-encrypted inner packet — never the source,
the final destination, or the payload (only the final hop sees the payload). So no single mix node
can link sender to receiver; combined with the padding + batching + cover already in `transport`,
that is the mixnet.

Per-hop key: `encapsulate(hop_pub)` (X-Wing ML-KEM-768 + X25519) -> a shared secret -> HKDF -> an
AEAD key that seals that hop's layer. Peeling decapsulates and opens it.

Reference of record: correctness + per-hop isolation. Production Sphinx also pads EVERY layer to a
constant size (so length doesn't reveal a hop's position or the route length) and carries replay
tags; those are noted follow-ups. `transport.MixnetBackend` composes this with padding/batching/cover.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence, Tuple

from ...crypto.kem import HybridKEMKeypair, HybridKEMPublic, decapsulate, encapsulate
from ...crypto.primitives import aead_decrypt, aead_encrypt, hkdf

_ONION_KEY = b"atlas/onion/hopkey/v1"
_TERMINAL = b"\x00"    # final layer: the payload follows
_RELAY = b"\x01"       # intermediate layer: next_hop_id ‖ inner OnionLayer follows


class OnionError(Exception):
    """Fail-closed — a wrong key or tampered layer never yields plaintext."""


@dataclass(frozen=True)
class OnionLayer:
    """One hop's layer: the KEM encapsulation (so the hop can derive its key) + the AEAD-sealed
    body. On the wire this is one opaque blob; only the holder of the hop's KEM key can open it."""

    mlkem_ct: bytes
    x25519_eph_pk: bytes
    sealed: bytes

    def to_bytes(self) -> bytes:
        return (len(self.mlkem_ct).to_bytes(4, "big") + self.mlkem_ct
                + len(self.x25519_eph_pk).to_bytes(4, "big") + self.x25519_eph_pk
                + self.sealed)

    @staticmethod
    def from_bytes(b: bytes) -> "OnionLayer":
        try:
            i = 0
            n = int.from_bytes(b[i:i + 4], "big"); i += 4
            ct = b[i:i + n]; i += n
            m = int.from_bytes(b[i:i + 4], "big"); i += 4
            pk = b[i:i + m]; i += m
            return OnionLayer(mlkem_ct=ct, x25519_eph_pk=pk, sealed=b[i:])
        except Exception as e:  # noqa: BLE001
            raise OnionError("malformed onion layer") from e


def _hop_key(shared: bytes, mlkem_ct: bytes) -> bytes:
    # Bind the AEAD key to THIS encapsulation's ciphertext (domain separation across layers).
    return hkdf(ikm=shared, info=_ONION_KEY + mlkem_ct)


def _wrap_one(inner: bytes, hop_pub: HybridKEMPublic) -> OnionLayer:
    enc = encapsulate(hop_pub)
    key = _hop_key(enc.shared, enc.mlkem_ct)
    sealed = aead_encrypt(key, inner, aad=b"")
    return OnionLayer(mlkem_ct=enc.mlkem_ct, x25519_eph_pk=enc.x25519_eph_pk, sealed=sealed)


def wrap(payload: bytes, route: Sequence[Tuple[bytes, HybridKEMPublic]]) -> OnionLayer:
    """Build the onion for `route` = [(hop_id, hop_pub), ...] in SEND order. Returns the OUTERMOST
    layer, handed to the first hop. Each hop's body carries the NEXT hop's id; the last hop's body
    carries the payload. `hop_id` is an opaque routing label (never the user's identity)."""
    if not route:
        raise OnionError("route must have at least one hop")
    inner = _TERMINAL + payload                      # innermost: final hop gets the payload
    layer = _wrap_one(inner, route[-1][1])
    for i in range(len(route) - 2, -1, -1):          # wrap outward
        next_hop_id = route[i + 1][0]
        body = _RELAY + len(next_hop_id).to_bytes(2, "big") + next_hop_id + layer.to_bytes()
        layer = _wrap_one(body, route[i][1])
    return layer


def peel(layer: OnionLayer, hop_kp: HybridKEMKeypair) -> Tuple[Optional[bytes], bytes]:
    """A hop peels its layer. Returns (next_hop_id, next):
      * `next_hop_id is None` and `next` is the PAYLOAD  -> this hop is the final destination;
      * else `next_hop_id` is the id to forward to and `next` is the serialized inner `OnionLayer`
        (parse with `OnionLayer.from_bytes`).
    Fail-closed: a layer not addressed to this hop, or tampered, raises `OnionError`."""
    shared = decapsulate(hop_kp, layer.mlkem_ct, layer.x25519_eph_pk)
    key = _hop_key(shared, layer.mlkem_ct)
    try:
        body = aead_decrypt(key, layer.sealed, aad=b"")
    except Exception as e:  # noqa: BLE001
        raise OnionError("cannot peel this layer (not addressed to this hop, or tampered)") from e
    tag, rest = body[:1], body[1:]
    if tag == _TERMINAL:
        return None, rest
    if tag == _RELAY:
        n = int.from_bytes(rest[:2], "big")
        return rest[2:2 + n], rest[2 + n:]
    raise OnionError("bad layer tag")
