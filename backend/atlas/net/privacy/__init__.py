"""Privacy transport — metadata protection for the relay path.

The relay stores-and-forwards OPAQUE blobs but still sees ENVELOPE METADATA:
from/to mailbox, blob SIZE, and ORDER/TIMING (``node_server.Envelope``). This package
removes the size/timing/volume signals while the node stays as blind to content as ever:

  * ``padding``   — quantise every message to a fixed SIZE bucket (applied to PLAINTEXT,
                    before sealing) so size reveals only the bucket.
  * ``batching``  — release blobs in fixed-count batches, padded with indistinguishable
                    COVER blobs, so timing and volume are decorrelated.
  * ``transport`` — compose the two over a pluggable delivery BACKEND (direct now;
                    Tor ``.onion`` / a PQC mixnet later, behind the same interface).

Python is the reference of record; a Swift parity port follows.
"""
from .batching import Batcher, OutboundItem
from .padding import BUCKETS, bucket_for, pad, unpad
from .transport import (
    Backend,
    BackendKind,
    DirectBackend,
    MixnetBackend,
    PrivacyChannel,
    TorBackend,
    make_backend,
)

__all__ = [
    "BUCKETS",
    "bucket_for",
    "pad",
    "unpad",
    "Batcher",
    "OutboundItem",
    "PrivacyChannel",
    "Backend",
    "BackendKind",
    "DirectBackend",
    "TorBackend",
    "MixnetBackend",
    "make_backend",
]
