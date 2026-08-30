"""Pluggable anchor backend — where public roots get published.

Both the private per-scope ledgers (`IndividualLedger`, per-conversation) and the PUBLIC economics
ledgers produce Merkle/commitment ROOTS; a backend publishes those roots to the public
accountability log. Only ROOTS cross this boundary — never content — so privacy is preserved
regardless of backend.

Today the default is `LocalBackend` (a `GlobalAnchorLog`, drand-bound, append-only). Later it swaps
for `ChainBackend` — the PoLE-consensus chain (a verified-human BFT validator set; consensus weight
is PERSONHOOD, never coin) — behind the SAME interface, so adopting the chain is a backend swap, not
a rewrite. Consensus itself is a documented research build behind this seam.
"""
from __future__ import annotations

from typing import Optional, Protocol

from .global_anchor import GlobalAnchorLog, GlobalReceipt


class LedgerBackend(Protocol):
    def publish(self, owner_id: bytes, root: bytes, epoch_round: bytes) -> GlobalReceipt: ...
    def latest(self, owner_id: bytes) -> Optional[bytes]: ...


class LocalBackend:
    """Default — a single-operator `GlobalAnchorLog`: real, drand-bound, append-only. The
    distributed witnessing is the deployment layer; the interface is already chain-shaped."""

    def __init__(self, log: Optional[GlobalAnchorLog] = None) -> None:
        self._log = log or GlobalAnchorLog()

    def publish(self, owner_id: bytes, root: bytes, epoch_round: bytes) -> GlobalReceipt:
        return self._log.anchor(owner_id, root, epoch_round)

    def latest(self, owner_id: bytes) -> Optional[bytes]:
        return self._log.latest_root(owner_id)

    def head(self) -> bytes:
        return self._log.head   # GlobalAnchorLog.head is a property


class ChainBackend:
    """STUB — publishes to the PoLE-consensus chain: a rotating set of verified-human validators
    running BFT, consensus weight = personhood (one verified human, one vote), NEVER coin-stake.
    Not built — requires the BFT protocol + validator set. Same interface, so it drops in for
    `LocalBackend` when the chain is ready. Do not implement the consensus casually; see the design."""

    def publish(self, owner_id: bytes, root: bytes, epoch_round: bytes) -> GlobalReceipt:  # pragma: no cover
        raise NotImplementedError("PoLE-consensus chain backend not built; see the consensus design")

    def latest(self, owner_id: bytes) -> Optional[bytes]:  # pragma: no cover
        raise NotImplementedError("PoLE-consensus chain backend not built; see the consensus design")
