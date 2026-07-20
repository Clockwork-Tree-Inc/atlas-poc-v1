"""Ledger / testnet stand-in for content anchoring (§8.1).

"anchor the content hash to a simple ledger/testnet stand-in (content
off-chain)." Only the content HASH is anchored — never the content. This is a
local append-only hash chain (each entry commits to the previous), the PoC
default the build spec left open (§8.1). Swap in a real testnet on the Mac.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..crypto.primitives import H


@dataclass(frozen=True)
class AnchorReceipt:
    index: int
    content_hash: bytes
    entry_hash: bytes      # H(prev_entry_hash || content_hash || index)
    prev_hash: bytes


class LedgerStub:
    """Append-only hash chain. Tamper-evident: changing any past entry breaks
    every subsequent entry_hash."""

    GENESIS = b"\x00" * 32

    def __init__(self):
        self._entries: list[AnchorReceipt] = []

    @property
    def head(self) -> bytes:
        return self._entries[-1].entry_hash if self._entries else self.GENESIS

    def anchor(self, content_hash: bytes) -> AnchorReceipt:
        prev = self.head
        idx = len(self._entries)
        entry_hash = H(b"atlas/ledger", prev, content_hash, idx.to_bytes(8, "big"))
        receipt = AnchorReceipt(index=idx, content_hash=content_hash,
                                entry_hash=entry_hash, prev_hash=prev)
        self._entries.append(receipt)
        return receipt

    def contains(self, content_hash: bytes) -> bool:
        return any(e.content_hash == content_hash for e in self._entries)

    def verify_chain(self) -> bool:
        prev = self.GENESIS
        for i, e in enumerate(self._entries):
            expect = H(b"atlas/ledger", prev, e.content_hash, i.to_bytes(8, "big"))
            if e.entry_hash != expect or e.prev_hash != prev:
                return False
            prev = e.entry_hash
        return True
