"""Onion packets over the hybrid PQ KEM (#51 Tier-2 core).

Properties:
  * ROUND-TRIP through H hops recovers the payload only at the final hop;
  * PER-HOP ISOLATION — each hop learns ONLY the next hop id and the still-sealed inner layer,
    never the payload or the final destination;
  * FAIL-CLOSED — a hop cannot peel a layer addressed to another hop; tampering is rejected.
"""
import pytest

from atlas.crypto.kem import generate_keypair
from atlas.net.privacy.onion import OnionError, OnionLayer, peel, wrap


def _hops(n):
    # each hop: (opaque routing id, keypair)
    return [(f"hop-{i}".encode(), generate_keypair()) for i in range(n)]


def test_three_hop_round_trip_and_isolation():
    hops = _hops(3)
    route = [(hid, kp.public) for hid, kp in hops]
    payload = b"the secret only the exit should see"

    outer = wrap(payload, route)

    # hop 0 peels -> learns to forward to hop-1, gets an inner layer (still sealed), NOT the payload
    nxt0, inner0 = peel(outer, hops[0][1])
    assert nxt0 == b"hop-1"
    assert payload not in inner0                      # hop 0 cannot see the payload

    # hop 1 peels -> forward to hop-2
    nxt1, inner1 = peel(OnionLayer.from_bytes(inner0), hops[1][1])
    assert nxt1 == b"hop-2"
    assert payload not in inner1                      # nor can hop 1

    # hop 2 (the exit) peels -> terminal: the payload
    nxt2, out = peel(OnionLayer.from_bytes(inner1), hops[2][1])
    assert nxt2 is None
    assert out == payload


def test_single_hop_delivers_payload():
    hops = _hops(1)
    route = [(hid, kp.public) for hid, kp in hops]
    outer = wrap(b"direct", route)
    nxt, out = peel(outer, hops[0][1])
    assert nxt is None and out == b"direct"


def test_wrong_hop_cannot_peel():
    hops = _hops(3)
    route = [(hid, kp.public) for hid, kp in hops]
    outer = wrap(b"payload", route)
    # hop 1's key cannot open hop 0's outer layer
    with pytest.raises(OnionError):
        peel(outer, hops[1][1])


def test_tampered_layer_is_rejected():
    hops = _hops(2)
    route = [(hid, kp.public) for hid, kp in hops]
    outer = wrap(b"payload", route)
    tampered = OnionLayer(mlkem_ct=outer.mlkem_ct, x25519_eph_pk=outer.x25519_eph_pk,
                          sealed=outer.sealed[:-1] + bytes([outer.sealed[-1] ^ 0x01]))
    with pytest.raises(OnionError):
        peel(tampered, hops[0][1])


def test_route_must_be_nonempty():
    with pytest.raises(OnionError):
        wrap(b"x", [])
