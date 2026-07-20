"""Alarm-triggered forensic window (C8).

On ANY alarm (panic code/phrase, improper disconnection, suspicious lifecycle,
failed-recovery escalation) the device seals its multimodal capture and streams
it OFF-DEVICE to the user's non-custodial storage as a forensic window.

DESIGN PROPERTIES (all enforced + tested):
  * ESCAPE-FIRST — the header (the wrapped content key) and the FIRST capture
    burst are sealed and emitted to the sink IMMEDIATELY on `open`, before any
    sustain loop, so the initial evidence is off-device before a coercer can
    react. Burst-then-sustain.
  * NO LOCAL BUFFER — plaintext is never retained. Each chunk is sealed and
    handed to the sink as it arrives; the window holds only the symmetric content
    key in RAM, never plaintext. (A local buffer is destroyable — so there isn't
    one.)
  * SEALED TO THE USER, NOT A BACKDOOR — the content key is KEM-wrapped
    (ML-KEM + X25519) to the USER's recovery public key. The storage host holds
    only opaque ciphertext; only the user (via the recovery structure) can open
    it. This is the user's evidence, not surveillance.
  * TIMESTAMP-ANCHORED — every chunk binds a beacon round (epoch id + randomness)
    as a real-world time witness for forensic credibility.
  * TAMPER-EVIDENT — chunks are hash-chained (prev_hash + chunk_hash). Dropping,
    reordering, or altering any chunk breaks the chain at verification.

Retrieval is via the recovery/guardian structure (`open_forensic_window` with the
recovery keypair). Escalation (peer/system check-in) is a policy layer on top and
is out of this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, List, Optional

from ..beacon.base import BeaconRound
from ..crypto import kem
from ..crypto.primitives import H, aead_decrypt, aead_encrypt, random_bytes
from .vault import Vault

_CHUNK_AAD = b"atlas/forensic/chunk"
GENESIS = b"\x00" * 32


class AlarmCause(Enum):
    PANIC_CODE = "panic_code"
    PANIC_PHRASE = "panic_phrase"
    IMPROPER_DISCONNECT = "improper_disconnect"
    SUSPICIOUS_LIFECYCLE = "suspicious_lifecycle"
    FAILED_RECOVERY = "failed_recovery"


@dataclass(frozen=True)
class ForensicHeader:
    """Emitted FIRST (escape-first). Carries the content key KEM-wrapped to the
    user's recovery public key — the storage host cannot unwrap it."""

    cause: str
    wrapped_key: dict            # kem-wrap {mlkem_ct, x25519_eph_pk, wrapped}
    genesis: bytes


@dataclass(frozen=True)
class ForensicChunk:
    seq: int
    cause: str
    beacon_drand_round: bytes       # timestamp anchor
    beacon_randomness: bytes
    prev_hash: bytes             # tamper-evident chain link
    ciphertext: bytes            # AES-256-GCM(content_key, capture) — nonce||ct
    chunk_hash: bytes

    @staticmethod
    def compute_hash(seq: int, cause: str, drand_round: bytes, randomness: bytes,
                     prev_hash: bytes, ciphertext: bytes) -> bytes:
        return H(b"atlas/forensic/link", seq.to_bytes(4, "big"), cause.encode(),
                 drand_round, randomness, prev_hash, ciphertext)


class ForensicWindow:
    """A live forensic window. Construct via `open(...)` (escape-first), then call
    `capture(...)` to sustain. Every artifact is emitted to `sink` sealed."""

    def __init__(self, *, cause: AlarmCause, content_key: bytes,
                 sink: Callable[[str, object], None]) -> None:
        self._cause = cause
        self._content_key = content_key          # RAM-only symmetric key; NO plaintext buffer
        self._sink = sink
        self._head = GENESIS
        self._seq = 0
        self._open = True

    @classmethod
    def open(cls, *, cause: AlarmCause, recovery_pub: kem.HybridKEMPublic,
             initial_capture: bytes, beacon_round: BeaconRound,
             sink: Callable[[str, object], None]) -> "ForensicWindow":
        """Fire the window: seal + emit the header AND the first capture burst
        IMMEDIATELY (escape-first), then return the window for sustaining."""
        content_key = random_bytes(32)
        header = ForensicHeader(
            cause=cause.value,
            wrapped_key=Vault.wrap_key_for_recipient(recovery_pub, content_key),
            genesis=GENESIS)
        sink("header", header)                   # off-device FIRST
        w = cls(cause=cause, content_key=content_key, sink=sink)
        w.capture(initial_capture, beacon_round)  # the initial burst, immediately
        return w

    def capture(self, plaintext: bytes, beacon_round: BeaconRound) -> ForensicChunk:
        """Seal one capture chunk, chain + anchor it, emit it, and DISCARD the
        plaintext. Never buffered locally."""
        if not self._open:
            raise RuntimeError("forensic window closed")
        self._seq += 1
        drand_round = beacon_round.drand_round()
        rnd = beacon_round.randomness
        ct = aead_encrypt(self._content_key, plaintext, aad=_CHUNK_AAD)
        chunk_hash = ForensicChunk.compute_hash(self._seq, self._cause.value, drand_round,
                                                rnd, self._head, ct)
        chunk = ForensicChunk(seq=self._seq, cause=self._cause.value, beacon_drand_round=drand_round,
                              beacon_randomness=rnd, prev_hash=self._head, ciphertext=ct,
                              chunk_hash=chunk_hash)
        self._head = chunk_hash
        self._sink("chunk", chunk)               # emitted; plaintext goes out of scope here
        return chunk

    def close(self) -> None:
        self._open = False


class ForensicTampering(Exception):
    """The forensic chain is broken (a chunk was dropped, reordered, or altered)."""


def open_forensic_window(header: ForensicHeader, chunks: List[ForensicChunk],
                         recovery_kp: kem.HybridKEMKeypair) -> List[bytes]:
    """USER side (holds the recovery key): unwrap the content key, verify the
    tamper-evident chain + anchors, and return the decrypted captures in order.
    Raises ForensicTampering if the chain is broken."""
    content_key = Vault.unwrap_key(recovery_kp, header.wrapped_key)
    prev = header.genesis
    out: List[bytes] = []
    for i, c in enumerate(chunks, start=1):
        if c.seq != i or c.prev_hash != prev:
            raise ForensicTampering(f"chain break at seq {c.seq} (drop/reorder)")
        expect = ForensicChunk.compute_hash(c.seq, c.cause, c.beacon_drand_round,
                                            c.beacon_randomness, c.prev_hash, c.ciphertext)
        if expect != c.chunk_hash:
            raise ForensicTampering(f"altered chunk at seq {c.seq}")
        out.append(aead_decrypt(content_key, c.ciphertext, aad=_CHUNK_AAD))
        prev = c.chunk_hash
    return out
