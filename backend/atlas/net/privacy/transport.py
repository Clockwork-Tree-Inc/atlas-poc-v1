"""Privacy transport — one send path composing length-hiding padding + batching/cover
traffic over a pluggable delivery BACKEND.

    plaintext --pad(to=cell)--> seal --> [uniform blob] --> Batcher --> Backend.deliver

The channel fixes a single ``cell`` size (like a mixnet cell / Sphinx packet), so every
sealed blob — real or cover — is the same length. Messages larger than one cell must be
chunked by the caller; chunking is a follow-up (a clear error is raised for now).

Backends are interchangeable behind ``Backend``: ``DirectBackend`` hands blobs straight
to a ``relay_send``-style sink today; ``TorBackend`` (and later a PQC mixnet) slot in
behind the same interface without touching the padding/batching logic above them.
``seal``/``open`` are injected so this module stays decoupled from the crypto core
(pass ``pqc_tunnel``'s seal/open in production).
"""
from __future__ import annotations

import os
from enum import Enum
from typing import Callable, List, Optional, Protocol

from .batching import Batcher, OutboundItem
from .padding import pad, unpad


class Backend(Protocol):
    """Delivers a finished batch of uniform blobs."""

    def deliver(self, batch: List[OutboundItem]) -> None: ...


class DirectBackend:
    """No network anonymity — but padding + batching still hide size/timing/volume from
    the relay. ``send`` is a ``relay_send``-style sink: ``send(to, blob)``."""

    def __init__(self, send: Callable[[str, bytes], None]) -> None:
        self._send = send

    def deliver(self, batch: List[OutboundItem]) -> None:
        for item in batch:
            self._send(item.to, item.blob)


class TorBackend:
    """STUB — same interface. Will route delivery over a SOCKS5 Tor proxy and reach the
    relay as a ``.onion`` hidden service (which also solves node reachability with no
    port-forward). Not wired yet."""

    def deliver(self, batch: List[OutboundItem]) -> None:  # pragma: no cover
        raise NotImplementedError("Tor backend not wired yet")


class MixnetBackend:
    """STUB — same interface. Atlas's own PQC mix network: Loopix-style continuous-time
    mixing + Sphinx packets over ML-KEM, run by verified-human node operators, adding
    per-hop reordering/batching/cover on top of what ``PrivacyChannel`` already does.
    The long-horizon complement to (or replacement for) Tor. Not built yet."""

    def deliver(self, batch: List[OutboundItem]) -> None:  # pragma: no cover
        raise NotImplementedError("mixnet backend not built yet")


class BackendKind(str, Enum):
    """The pluggable delivery options. ``DIRECT`` works today; ``TOR`` and ``MIXNET``
    are stubs behind the identical interface, so a channel can be pointed at any of them
    without touching the padding/batching above it."""

    DIRECT = "direct"
    TOR = "tor"
    MIXNET = "mixnet"


def make_backend(
    kind: "BackendKind | str", *, send: Optional[Callable[[str, bytes], None]] = None
) -> Backend:
    """Construct a delivery backend by option. ``DIRECT`` needs a ``send(to, blob)``
    sink (e.g. a ``relay_send`` wrapper); ``TOR``/``MIXNET`` return their stubs."""
    kind = BackendKind(kind)
    if kind is BackendKind.DIRECT:
        if send is None:
            raise ValueError("direct backend needs a send(to, blob) sink")
        return DirectBackend(send)
    if kind is BackendKind.TOR:
        return TorBackend()
    return MixnetBackend()


class PrivacyChannel:
    """Compose padding + batching + a delivery backend into one send path."""

    def __init__(
        self,
        *,
        backend: Backend,
        seal: Callable[[bytes], bytes],
        batch_size: int,
        cover_recipient: Callable[[], str],
        cell: int = 4096,
        rng: Callable[[int], bytes] = os.urandom,
    ) -> None:
        self._backend = backend
        self._seal = seal
        self._cell = cell
        # Derive the uniform sealed-blob size once, from a probe, so cover blobs match
        # real ones exactly. (seal may be randomised; only its output LENGTH matters.)
        self._blob_size = len(seal(pad(b"", to=cell)))
        self._batcher = Batcher(
            batch_size=batch_size,
            blob_size=self._blob_size,
            cover_recipient=cover_recipient,
            rng=rng,
        )

    @property
    def blob_size(self) -> int:
        """The uniform on-wire size of every blob (real and cover)."""
        return self._blob_size

    def pending(self) -> int:
        return self._batcher.pending()

    def send(self, to: str, plaintext: bytes) -> None:
        """Pad to the cell, seal, and queue for the next batch flush."""
        blob = self._seal(pad(plaintext, to=self._cell))
        if len(blob) != self._blob_size:
            raise ValueError(
                "sealed blob size drifted from the channel cell — is seal deterministic "
                f"in length? got {len(blob)}B, expected {self._blob_size}B"
            )
        self._batcher.enqueue(to, blob)

    def flush(self) -> None:
        """Release one constant-size batch (real + cover) to the backend."""
        self._backend.deliver(self._batcher.flush())

    @staticmethod
    def receive(blob: bytes, open_: Callable[[bytes], bytes]) -> Optional[bytes]:
        """Recover a message from a received blob, or ``None`` if it is cover/garbage.

        Cover blobs are random bytes: ``open_`` (a real AEAD open) raises on them, and a
        malformed frame trips ``unpad`` — both mean "not for me / cover", so we drop
        them silently rather than surface an error."""
        try:
            return unpad(open_(blob))
        except Exception:
            return None
