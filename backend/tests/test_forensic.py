"""C8 — alarm-triggered forensic window: escape-first, host-blind, sealed to the
user's recovery key, timestamp-anchored, tamper-evident, no local plaintext buffer.
"""

import pytest

from atlas.beacon import LocalBeacon
from atlas.crypto import kem
from atlas.session.forensic import (
    AlarmCause, ForensicChunk, ForensicTampering, ForensicWindow, open_forensic_window,
)


def _sink():
    events = []
    return events, (lambda kind, obj: events.append((kind, obj)))


def _beacon():
    return LocalBeacon(period_s=3.0)


def test_escape_first_emits_header_and_first_burst_immediately():
    """On open, the header (wrapped key) AND the first capture burst are sealed
    and emitted BEFORE any sustain loop — evidence is off-device immediately."""
    events, sink = _sink()
    rec = kem.generate_keypair()
    b = _beacon()
    ForensicWindow.open(cause=AlarmCause.PANIC_CODE, recovery_pub=rec.public,
                        initial_capture=b"BURST-0 audio+video", beacon_round=b.round_at(1.0), sink=sink)
    kinds = [k for k, _ in events]
    assert kinds == ["header", "chunk"]          # header first, then the initial burst
    assert events[1][1].seq == 1


def test_storage_host_cannot_read_only_recovery_key_opens():
    """The sink (storage host) receives only opaque sealed artifacts. The content
    is unreadable without the USER's recovery key."""
    events, sink = _sink()
    rec = kem.generate_keypair()
    b = _beacon()
    w = ForensicWindow.open(cause=AlarmCause.IMPROPER_DISCONNECT, recovery_pub=rec.public,
                            initial_capture=b"frame-0", beacon_round=b.round_at(1.0), sink=sink)
    w.capture(b"frame-1", b.round_at(4.0))
    header = events[0][1]
    chunks = [o for k, o in events if k == "chunk"]

    # host sees no plaintext anywhere
    assert b"frame-0" not in repr(events).encode() and b"frame-1" not in repr(events).encode()
    # wrong key cannot open
    with pytest.raises(Exception):
        open_forensic_window(header, chunks, kem.generate_keypair())
    # the real recovery key recovers the captures in order
    assert open_forensic_window(header, chunks, rec) == [b"frame-0", b"frame-1"]


def test_no_local_plaintext_buffer():
    """The window retains only the symmetric content key — never plaintext."""
    events, sink = _sink()
    rec = kem.generate_keypair()
    b = _beacon()
    w = ForensicWindow.open(cause=AlarmCause.SUSPICIOUS_LIFECYCLE, recovery_pub=rec.public,
                            initial_capture=b"secret-capture", beacon_round=b.round_at(1.0), sink=sink)
    w.capture(b"secret-capture-2", b.round_at(4.0))
    assert b"secret-capture" not in repr(vars(w)).encode()


def test_timestamp_anchored():
    events, sink = _sink()
    rec = kem.generate_keypair()
    b = _beacon()
    ra, rb = b.round_at(1.0), b.round_at(9.0)
    w = ForensicWindow.open(cause=AlarmCause.FAILED_RECOVERY, recovery_pub=rec.public,
                            initial_capture=b"c0", beacon_round=ra, sink=sink)
    w.capture(b"c1", rb)
    chunks = [o for k, o in events if k == "chunk"]
    assert chunks[0].beacon_drand_round == ra.drand_round()
    assert chunks[1].beacon_drand_round == rb.drand_round()


def test_tamper_evident_dropped_chunk_detected():
    events, sink = _sink()
    rec = kem.generate_keypair()
    b = _beacon()
    w = ForensicWindow.open(cause=AlarmCause.PANIC_PHRASE, recovery_pub=rec.public,
                            initial_capture=b"c0", beacon_round=b.round_at(1.0), sink=sink)
    w.capture(b"c1", b.round_at(4.0))
    w.capture(b"c2", b.round_at(7.0))
    header = events[0][1]
    chunks = [o for k, o in events if k == "chunk"]
    # a coercer drops the middle chunk -> chain breaks
    with pytest.raises(ForensicTampering):
        open_forensic_window(header, [chunks[0], chunks[2]], rec)


def test_tamper_evident_altered_chunk_detected():
    events, sink = _sink()
    rec = kem.generate_keypair()
    b = _beacon()
    w = ForensicWindow.open(cause=AlarmCause.PANIC_CODE, recovery_pub=rec.public,
                            initial_capture=b"c0", beacon_round=b.round_at(1.0), sink=sink)
    w.capture(b"c1", b.round_at(4.0))
    header = events[0][1]
    chunks = [o for k, o in events if k == "chunk"]
    # flip a byte in a chunk's ciphertext, keep its stored hash -> hash mismatch
    bad = chunks[1]
    tampered = ForensicChunk(seq=bad.seq, cause=bad.cause, beacon_drand_round=bad.beacon_drand_round,
                             beacon_randomness=bad.beacon_randomness, prev_hash=bad.prev_hash,
                             ciphertext=bad.ciphertext[:-1] + bytes([bad.ciphertext[-1] ^ 0xFF]),
                             chunk_hash=bad.chunk_hash)
    with pytest.raises(ForensicTampering):
        open_forensic_window(header, [chunks[0], tampered], rec)


def test_reordered_chunks_detected():
    events, sink = _sink()
    rec = kem.generate_keypair()
    b = _beacon()
    w = ForensicWindow.open(cause=AlarmCause.PANIC_CODE, recovery_pub=rec.public,
                            initial_capture=b"c0", beacon_round=b.round_at(1.0), sink=sink)
    w.capture(b"c1", b.round_at(4.0))
    header = events[0][1]
    chunks = [o for k, o in events if k == "chunk"]
    with pytest.raises(ForensicTampering):
        open_forensic_window(header, [chunks[1], chunks[0]], rec)
