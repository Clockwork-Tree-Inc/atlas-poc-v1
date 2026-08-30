"""Distributed custody + rotation for the SERVER HALF of the two-tier TSK.

Turns the tested `tsk_two_tier` primitive into the real "sharded over rotating nodes" property.
`server_half` (independent of the seed; useless without a threshold of YOUR holders) is Shamir
k-of-m split across a set of institutional NODES. Each node stores only an OPAQUE sealed blob,
indexed by a blinded LOCATOR:

  * BLIND — the share is sealed under a key only the recovering user can re-derive (from the
    recovery key), so a node stores ciphertext it cannot open — the same posture as the blind relay.
  * UNLINKABLE — the locator is H(recovery_selector, node_id, epoch), so a node cannot tell whose
    share it holds, and one user's shares on different nodes are mutually unlinkable.
  * USELESS-ALONE — even in the clear a server-half share reveals nothing about the seed (XOR
    one-time-pad with user_half), and reconstruction still needs a threshold of YOUR holders. The
    seal is defence in depth, not the thing standing between the node and your identity.

ROTATION re-shares to a fresh (possibly different) node set at a new epoch, so no fixed node set
holds a share long-term; the old locators are dropped. The CLIENT — the only party that can derive
the recovery key — performs rotation by reconstructing `server_half` (which, being independent of
the seed, never exposes the TSK) and re-splitting with fresh Shamir randomness. Nodes only ever
store / return / drop opaque blobs.

Reference of record. Swift parity: ios/AtlasCore/Sources/AtlasCore/Keys/ServerCustody.swift.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence, Tuple

from ..crypto import shamir
from ..crypto.primitives import H, aead_decrypt, aead_encrypt, hkdf, random_bytes
from ..recovery.threshold_seal import ThresholdPolicy

_LOCATOR = b"atlas/custody/locator/v1"
_SEAL = b"atlas/custody/seal/v1"


class CustodyError(Exception):
    """Base — fail-closed."""


class ThresholdNotMet(CustodyError):
    """Fewer than k custody shares were retrieved — server_half cannot be reassembled."""


@dataclass(frozen=True)
class CustodianNode:
    """An eligible server-half custodian. The crypto layer needs only a stable id; the network
    address is carried by the net layer (share_custody endpoints on node_server)."""
    node_id: str


@dataclass(frozen=True)
class CustodyPlacement:
    """One placed share: which node holds it, under which (blinded) locator, and the opaque blob."""
    node_id: str
    locator: bytes        # H(recovery_selector, node_id, epoch) — opaque to the node
    blob: bytes           # AEAD(seal_key(locator), share.encode(), aad=locator)
    epoch: int


def _locator(recovery_selector: bytes, node_id: str, epoch: int) -> bytes:
    return H(_LOCATOR, recovery_selector, node_id.encode("utf-8"), epoch.to_bytes(4, "big"))


def _seal_key(recovery_key: bytes, locator: bytes) -> bytes:
    # Per-share key bound to the locator, so a blob is only openable at its own locator.
    return hkdf(ikm=recovery_key, info=_SEAL + locator, length=32)


def distribute_server_half(
    server_half: bytes,
    *,
    nodes: Sequence[CustodianNode],
    policy: ThresholdPolicy,
    recovery_selector: bytes,
    recovery_key: bytes,
    epoch: int = 0,
    rng=None,
) -> List[CustodyPlacement]:
    """Shamir k-of-m split `server_half` across `nodes`, sealing each share under a per-locator key.
    `nodes` must number exactly `policy.n`. Returns the placements to push to the nodes."""
    if len(nodes) != policy.n:
        raise ValueError(f"policy expects n={policy.n} nodes, got {len(nodes)}")
    if len({n.node_id for n in nodes}) != len(nodes):
        raise ValueError("custodian node_ids must be distinct")
    raw = shamir.split(server_half, n=policy.n, k=policy.m)
    placements: List[CustodyPlacement] = []
    for node, share in zip(nodes, raw):
        loc = _locator(recovery_selector, node.node_id, epoch)
        blob = aead_encrypt(_seal_key(recovery_key, loc), share.encode(), aad=loc)
        placements.append(CustodyPlacement(node_id=node.node_id, locator=loc, blob=blob, epoch=epoch))
    return placements


def collect_server_half(
    retrieved: Sequence[Tuple[bytes, bytes]],   # (locator, blob) pairs fetched from >= k nodes
    *,
    policy: ThresholdPolicy,
    recovery_key: bytes,
) -> bytes:
    """Open >= k retrieved blobs and Shamir-combine them back to `server_half`. Fail-closed below
    threshold. A blob only opens under the key derived from its own locator, so a wrong/foreign
    blob fails the AEAD tag rather than silently corrupting the result."""
    if len(retrieved) < policy.m:
        raise ThresholdNotMet(f"need {policy.m} custody shares, got {len(retrieved)}")
    shares: List[shamir.Share] = []
    for loc, blob in retrieved:
        share_bytes = aead_decrypt(_seal_key(recovery_key, loc), blob, aad=loc)
        shares.append(shamir.Share.decode(share_bytes))
    return shamir.combine(shares)


def rotate_server_half(
    retrieved: Sequence[Tuple[bytes, bytes]],
    *,
    all_old_locators: Sequence[bytes],
    policy: ThresholdPolicy,
    recovery_selector: bytes,
    recovery_key: bytes,
    new_nodes: Sequence[CustodianNode],
    new_epoch: int,
    rng=None,
) -> Tuple[List[CustodyPlacement], List[bytes]]:
    """Proactive re-share. Reconstruct `server_half` from >= k retrieved shares, then re-split it
    FRESH to `new_nodes` at `new_epoch`. Returns (new_placements, drop_locators).

    `retrieved` is the k (locator, blob) pairs fetched to rebuild; `all_old_locators` is EVERY old
    locator so rotation retires them all — including nodes not read for the reconstruct, so no
    stale share lingers anywhere. Reconstructing `server_half` here never exposes the TSK (it is
    independent of the seed); the fresh Shamir randomness makes the old shares useless against the
    new set, so no fixed node set holds a usable share across a rotation."""
    server_half = collect_server_half(retrieved, policy=policy, recovery_key=recovery_key)
    new_placements = distribute_server_half(
        server_half, nodes=new_nodes, policy=policy,
        recovery_selector=recovery_selector, recovery_key=recovery_key,
        epoch=new_epoch, rng=rng,
    )
    return new_placements, list(all_old_locators)
