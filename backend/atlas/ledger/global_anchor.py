"""Global anchoring of individual-ledger roots (TRUST_LAYER.md #8).

The decentralized global ledger where per-owner individual-ledger ROOTS are checkpointed,
each bound to a **drand round** (the decentralized, verifiable timekeeper). Only commitments
(roots) are anchored — never content, never even the individual leaves. A third party who
trusts the global log + drand can later verify a single message's inclusion against an
anchored root, learning only that message.

PoC deployment: this append-only hash chain stands in for the real "drand/beacon + blockchain
now; satellite checkpoint later" substrate. The drand-round binding is real; the chain is the
local stand-in for the distributed log. Tamper-evident: altering any past anchor breaks every
later `entry_hash`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from ..crypto.primitives import H

_GLOBAL = b"atlas/global-anchor"


def _lp(b: bytes) -> bytes:
    """Length-prefix framing so a variable-length field cannot collide with the next."""
    return len(b).to_bytes(4, "big") + b


@dataclass(frozen=True)
class GlobalReceipt:
    index: int
    owner_id: bytes
    anchored_root: bytes      # the individual ledger's Merkle root at anchor time
    drand_round: bytes        # decentralized timekeeper binding
    entry_hash: bytes
    prev_hash: bytes


class GlobalAnchorLog:
    """Append-only chain of `(owner_id, root, drand_round)` checkpoints.

    HONEST BOUNDARY: this single local chain is tamper-EVIDENT (any edit breaks a later
    `entry_hash`), but it does NOT by itself prevent EQUIVOCATION — a malicious operator could keep
    two divergent chains and show different ones to different parties. Non-equivocation requires the
    real decentralized substrate (drand beacon + a public blockchain + satellite checkpoints); the
    drand-round binding here is real, the distributed witnessing is the deployment layer (#15)."""

    GENESIS = b"\x00" * 32

    def __init__(self) -> None:
        self._entries: List[GlobalReceipt] = []
        self._last_round = -1

    @property
    def head(self) -> bytes:
        return self._entries[-1].entry_hash if self._entries else self.GENESIS

    def anchor(self, owner_id: bytes, root: bytes, drand_round: bytes) -> GlobalReceipt:
        # drand rounds only move forward — reject a backdated (non-monotonic) round so timestamps
        # cannot be rewound.
        r = int.from_bytes(drand_round, "big")
        if self._entries and r < self._last_round:
            raise ValueError("drand_round must be non-decreasing (no backdating)")
        prev = self.head
        idx = len(self._entries)
        # length-prefix EVERY variable-length field (owner_id, root, drand_round) so no byte can
        # migrate across a boundary and collide two distinct (owner, root, round) tuples onto one
        # entry_hash. Defense-in-depth: today root is fixed-width, but the framing must not depend
        # on that. idx is fixed 8 bytes.
        entry_hash = H(_GLOBAL, prev, _lp(owner_id), _lp(root), _lp(drand_round),
                       idx.to_bytes(8, "big"))
        receipt = GlobalReceipt(index=idx, owner_id=owner_id, anchored_root=root,
                                drand_round=drand_round, entry_hash=entry_hash, prev_hash=prev)
        self._entries.append(receipt)
        self._last_round = r
        return receipt

    def latest_root(self, owner_id: bytes) -> Optional[bytes]:
        """The most recently anchored root for `owner_id` (None if never anchored)."""
        for e in reversed(self._entries):
            if e.owner_id == owner_id:
                return e.anchored_root
        return None

    def is_anchored(self, owner_id: bytes, root: bytes) -> bool:
        """Was this exact `(owner_id, root)` ever checkpointed here?"""
        return any(e.owner_id == owner_id and e.anchored_root == root for e in self._entries)

    def verify_chain(self) -> bool:
        # A third-party verifier must re-derive EVERY property the append path enforces —
        # including that drand rounds are non-decreasing. Otherwise a producer (the party the
        # equivocation boundary already distrusts) can hand-build a hash-consistent chain with
        # REWOUND rounds and it would verify, defeating the timestamp-rewind protection.
        prev = self.GENESIS
        last_round = -1
        for i, e in enumerate(self._entries):
            expect = H(_GLOBAL, prev, _lp(e.owner_id), _lp(e.anchored_root), _lp(e.drand_round),
                       i.to_bytes(8, "big"))
            if e.entry_hash != expect or e.prev_hash != prev or e.index != i:
                return False
            r = int.from_bytes(e.drand_round, "big")
            if r < last_round:
                return False               # backdated round — same rule anchor() enforces
            last_round = r
            prev = e.entry_hash
        return True
