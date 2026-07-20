"""Individual (per-user / per-space) append-only ledger of COMMITMENTS (TRUST_LAYER.md #8).

An owner (a user's System-ID handle, or a space id) keeps an append-only Merkle accumulator.
It only ever holds **commitments** — hiding+binding hashes of content, never content itself.
Its `root` is a compact commitment to the whole history, which the global anchor publishes.

The commitment is `H(domain, opening, content)`: HIDING (a fresh random `opening` keeps the
content secret) and BINDING (H). "Selectively provable later" = reveal `(content, opening)` for
ONE message and show its Merkle inclusion against an anchored root — revealing nothing else.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from ..crypto.primitives import H, random_bytes
from . import merkle

_COMMIT = b"atlas/ledger-commit"


def commit(content: bytes, opening: bytes | None = None) -> tuple[bytes, bytes]:
    """Return `(commitment, opening)`. Pass `opening` to reproduce a known commitment
    (verification); omit it to mint a fresh hiding commitment."""
    if opening is None:
        opening = random_bytes(32)
    return H(_COMMIT, opening, content), opening


@dataclass(frozen=True)
class InclusionProof:
    """A compact proof that `commitment` (at `index`) is under `root`."""

    commitment: bytes
    index: int
    path: list[merkle.ProofStep]
    root: bytes

    def verify(self) -> bool:
        return merkle.verify_inclusion(self.commitment, self.path, self.root)


@dataclass
class IndividualLedger:
    """Per-owner commitment ledger. `owner_id` binds it to a user or space; the global anchor
    records `(owner_id, root, drand_round)` so two owners never share authority over a root even if
    their leaves coincide.

    Append via `append()` only. HONEST BOUNDARY: this is tamper-EVIDENT, not structurally immutable
    — any edit to a past leaf changes the Merkle `root`, which no longer matches the root that was
    anchored globally, so the tampering is DETECTED at comparison against the anchor. The
    append-only / immutability guarantee comes from the anchoring, not from the in-memory list."""

    owner_id: bytes
    _leaves: List[bytes] = field(default_factory=list, repr=False)

    def append(self, commitment: bytes) -> int:
        """Append a commitment; returns its leaf index. Content is NEVER passed here — only
        its commitment (see `commit`)."""
        self._leaves.append(commitment)
        return len(self._leaves) - 1

    def __len__(self) -> int:
        return len(self._leaves)

    @property
    def root(self) -> bytes:
        """Current Merkle root — the commitment to anchor globally."""
        return merkle.merkle_root(self._leaves)

    def contains(self, commitment: bytes) -> bool:
        return commitment in self._leaves

    def prove(self, index: int) -> InclusionProof:
        """Inclusion proof for the leaf at `index`, against the CURRENT root."""
        if not 0 <= index < len(self._leaves):
            raise IndexError("leaf index out of range")
        return InclusionProof(commitment=self._leaves[index], index=index,
                              path=merkle.inclusion_proof(self._leaves, index),
                              root=self.root)
