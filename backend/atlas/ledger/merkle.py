"""Binary Merkle tree over commitments (TRUST_LAYER.md #8).

Gives a compact `root` to anchor globally and O(log n) inclusion proofs, so a single
message can later be proven to have been in a ledger — revealing ONLY that message — against
a root that was published (anchored) at a point in time.

Domain-separated hashing (leaf vs node) prevents second-preimage games across the two.
Odd nodes are PROMOTED unchanged to the next level (no last-leaf duplication), so the tree
is unambiguous for any leaf count. All hashes use the protocol `H` (SHA3-256), so this is
byte-parity-critical: the Swift mirror must reproduce it exactly.
"""

from __future__ import annotations

from typing import List, Sequence, Tuple

from ..crypto.primitives import H

_LEAF = b"atlas/merkle-leaf"
_NODE = b"atlas/merkle-node"
_EMPTY = b"atlas/merkle-empty"

# One proof step: (sibling_hash, sibling_is_on_the_right).
ProofStep = Tuple[bytes, bool]


def leaf_hash(commitment: bytes) -> bytes:
    return H(_LEAF, commitment)


def _node(left: bytes, right: bytes) -> bytes:
    return H(_NODE, left, right)


def empty_root() -> bytes:
    return H(_EMPTY)


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    """Root of the tree over `leaves` (each a commitment). Empty tree -> a fixed sentinel."""
    if not leaves:
        return empty_root()
    level = [leaf_hash(x) for x in leaves]
    while len(level) > 1:
        level = _next_level(level)
    return level[0]


def inclusion_proof(leaves: Sequence[bytes], index: int) -> List[ProofStep]:
    """Authentication path proving `leaves[index]` sits under `merkle_root(leaves)`."""
    if not 0 <= index < len(leaves):
        raise IndexError("leaf index out of range")
    level = [leaf_hash(x) for x in leaves]
    idx = index
    proof: List[ProofStep] = []
    while len(level) > 1:
        sib = idx ^ 1
        if sib < len(level):
            proof.append((level[sib], sib > idx))  # sibling to the right?
        # else: idx is a promoted odd node this level — no sibling
        level = _next_level(level)
        idx //= 2
    return proof


def verify_inclusion(commitment: bytes, proof: Sequence[ProofStep], root: bytes) -> bool:
    """Recompute the root from a leaf commitment + its authentication path."""
    h = leaf_hash(commitment)
    for sibling, sibling_is_right in proof:
        h = _node(h, sibling) if sibling_is_right else _node(sibling, h)
    return h == root


def _next_level(level: List[bytes]) -> List[bytes]:
    nxt: List[bytes] = []
    for i in range(0, len(level), 2):
        if i + 1 < len(level):
            nxt.append(_node(level[i], level[i + 1]))
        else:
            nxt.append(level[i])  # promote odd node unchanged
    return nxt
