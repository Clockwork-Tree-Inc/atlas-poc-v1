"""Batching + cover traffic — decorrelate send TIMING and VOLUME.

Outbound blobs are buffered and released in fixed-count batches. When fewer real
blobs than the target are queued at flush time, indistinguishable COVER blobs pad the
batch up to a constant count. Combined with fixed-size padding (so every blob is the
same length), the relay sees a steady stream of identical-looking envelopes and cannot
infer who spoke, when, or how much.

A cover blob is just ``blob_size`` random bytes addressed to a caller-chosen recipient.
It is *not* sealed real plaintext, so the recipient's AEAD open fails and it is silently
dropped (see ``transport.PrivacyChannel.receive``) — no cover marker is needed on the
wire, which is what keeps cover and real blobs indistinguishable to the node.

Flushing is explicit (a scheduler calls ``flush`` on a fixed cadence = constant rate).
Poisson/timed release is a thin wrapper left for later; the deterministic core is here.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, List


@dataclass
class OutboundItem:
    """One blob queued for delivery. ``cover`` is bookkeeping for the sender/tests only
    — it is never serialised, so it cannot leak to the relay."""
    to: str
    blob: bytes
    cover: bool = False


class Batcher:
    """Fixed-count batcher with constant-rate cover fill."""

    def __init__(
        self,
        *,
        batch_size: int,
        blob_size: int,
        cover_recipient: Callable[[], str],
        rng: Callable[[int], bytes] = os.urandom,
    ) -> None:
        if batch_size < 1:
            raise ValueError("batch_size must be >= 1")
        if blob_size < 1:
            raise ValueError("blob_size must be >= 1")
        self.batch_size = batch_size
        self.blob_size = blob_size
        self._cover_recipient = cover_recipient
        self._rng = rng
        self._queue: List[OutboundItem] = []

    def enqueue(self, to: str, blob: bytes) -> None:
        """Queue a real blob. It MUST already be padded to the channel's blob size, so
        it is indistinguishable from cover on the wire."""
        if len(blob) != self.blob_size:
            raise ValueError(
                f"blob is {len(blob)}B, not the channel bucket {self.blob_size}B"
            )
        self._queue.append(OutboundItem(to, blob, cover=False))

    def pending(self) -> int:
        """Real blobs still waiting for a flush."""
        return len(self._queue)

    def _cover(self) -> OutboundItem:
        return OutboundItem(self._cover_recipient(), self._rng(self.blob_size), cover=True)

    def flush(self) -> List[OutboundItem]:
        """Release exactly ``batch_size`` items: real blobs first (up to batch_size),
        then cover blobs to fill. Always returns a full batch — even with an empty
        queue — so the output rate is constant."""
        batch = self._queue[: self.batch_size]
        self._queue = self._queue[self.batch_size :]
        while len(batch) < self.batch_size:
            batch.append(self._cover())
        return batch
