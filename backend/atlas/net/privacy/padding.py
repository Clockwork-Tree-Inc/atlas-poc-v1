"""Length-hiding padding — quantise a message to a fixed set of SIZE buckets so the
relay (which sees only the opaque blob's size, per ``node_server.Envelope``) learns the
bucket, not the true length.

MUST be applied to PLAINTEXT, before sealing:  ``pad -> seal -> send``; the recipient
does ``open -> unpad``. Padding the *ciphertext* instead would leave the length header
readable by the node, defeating the purpose — so padding lives above the seal.

The fill is zero bytes: it is fine because the padded blob is sealed afterwards (the
AEAD randomises the whole thing), and zero fill keeps the reference deterministic.
"""
from __future__ import annotations

import struct

# Fixed size ladder, in bytes, of the framed body (4-byte length header + payload).
# A short ladder keeps the number of distinguishable sizes small while bounding the
# worst-case padding overhead to <4x.
BUCKETS: tuple[int, ...] = (256, 1024, 4096, 16384, 65536, 262144, 1048576)

_HEADER = 4  # big-endian uint32 true-length prefix
_MAX = 1 << 32


def bucket_for(n: int) -> int:
    """Smallest total blob size that holds ``n`` payload bytes (incl. the header).

    Beyond the top of the ladder, round up to a whole multiple of the largest bucket
    so even oversized messages stay quantised.
    """
    if n < 0:
        raise ValueError("length must be non-negative")
    need = n + _HEADER
    for b in BUCKETS:
        if need <= b:
            return b
    top = BUCKETS[-1]
    return ((need + top - 1) // top) * top


def pad(data: bytes, *, to: int | None = None) -> bytes:
    """Frame ``data`` as ``uint32(len) || data || zero-fill`` sized to a bucket.

    ``to`` forces an exact target size (used by a fixed-cell channel); it must be at
    least ``len(data) + 4``. Without it, the smallest fitting ladder bucket is used.
    """
    if len(data) >= _MAX:
        raise ValueError("message too large to pad")
    body = struct.pack(">I", len(data)) + data
    if to is None:
        size = bucket_for(len(data))
    else:
        if to < len(body):
            raise ValueError(f"message ({len(body)}B framed) exceeds cell size {to}B")
        size = to
    return body + b"\x00" * (size - len(body))


def unpad(blob: bytes) -> bytes:
    """Recover the original bytes from a padded blob. Raises on a malformed frame."""
    if len(blob) < _HEADER:
        raise ValueError("blob too short to be padded")
    (n,) = struct.unpack(">I", blob[:_HEADER])
    if _HEADER + n > len(blob):
        raise ValueError("padded length header exceeds blob")
    return blob[_HEADER:_HEADER + n]
