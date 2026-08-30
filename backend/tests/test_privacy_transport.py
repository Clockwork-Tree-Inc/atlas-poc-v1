"""Privacy transport: length-hiding padding + batching/cover traffic over a pluggable
backend. Asserts the relay-visible signals (size, timing/volume) are flattened while
content stays recoverable end-to-end."""
import pytest

from atlas.net.privacy import (
    BUCKETS,
    Batcher,
    BackendKind,
    DirectBackend,
    MixnetBackend,
    PrivacyChannel,
    TorBackend,
    bucket_for,
    make_backend,
    pad,
    unpad,
)

# --- a toy length-preserving "seal": deterministic length, distinguishable from cover.
_TAG = b"SEAL"


def _seal(p: bytes) -> bytes:
    return _TAG + p


def _open(c: bytes) -> bytes:
    if not c.startswith(_TAG):
        raise ValueError("bad tag")  # cover / not-for-me -> receive() returns None
    return c[len(_TAG):]


# ------------------------------- padding ----------------------------------------

def test_pad_roundtrips_and_quantises_to_a_bucket():
    for n in [0, 1, 100, 255, 256, 257, 4096, 100_000]:
        data = b"x" * n
        blob = pad(data)
        assert unpad(blob) == data
        assert len(blob) == bucket_for(n)


def test_pad_kat_parity_vector():
    # Shared cross-impl vector with ios/AtlasCore/Tests/.../PrivacyTransportTests.swift
    assert pad(b"atlas", to=16).hex() == "0000000561746c617300000000000000"
    assert bucket_for(1) == 256
    assert bucket_for(256 - 4) == 256 and bucket_for(256 - 3) == 1024


def test_everything_in_a_bucket_hits_the_same_size():
    sizes = {len(pad(b"x" * n)) for n in range(1, 240)}  # all well under bucket 256
    assert sizes == {256}


def test_bucket_ladder_then_multiple_of_top_for_oversize():
    assert bucket_for(1) == 256
    assert bucket_for(256 - 4) == 256 and bucket_for(256 - 3) == 1024
    top = BUCKETS[-1]
    big = top * 3  # beyond the ladder
    assert bucket_for(big) == ((big + 4 + top - 1) // top) * top
    assert len(pad(b"z" * big)) % top == 0


def test_pad_to_forces_exact_cell_and_rejects_overflow():
    assert len(pad(b"hi", to=4096)) == 4096
    with pytest.raises(ValueError):
        pad(b"x" * 4096, to=4096)  # 4096 + 4-byte header > cell


def test_unpad_rejects_garbage():
    with pytest.raises(ValueError):
        unpad(b"\x00")  # shorter than the header
    with pytest.raises(ValueError):
        unpad(b"\xff\xff\xff\xff")  # header claims 4GiB in a 4-byte blob


# ------------------------------- batching ---------------------------------------

def _const_rng(n: int) -> bytes:
    return b"\xff" * n


def _batcher(batch_size=4, blob_size=260):
    return Batcher(
        batch_size=batch_size,
        blob_size=blob_size,
        cover_recipient=lambda: "decoy",
        rng=_const_rng,
    )


def test_enqueue_requires_channel_blob_size():
    b = _batcher(blob_size=260)
    with pytest.raises(ValueError):
        b.enqueue("to", b"short")


def test_flush_fills_short_batch_with_cover_constant_rate():
    b = _batcher(batch_size=4, blob_size=260)
    b.enqueue("alice", b"\x01" * 260)
    batch = b.flush()
    assert len(batch) == 4                       # constant rate: always a full batch
    reals = [i for i in batch if not i.cover]
    covers = [i for i in batch if i.cover]
    assert len(reals) == 1 and len(covers) == 3
    assert reals[0].to == "alice"
    assert all(c.to == "decoy" and len(c.blob) == 260 for c in covers)  # indistinguishable size


def test_empty_queue_still_emits_full_cover_batch():
    b = _batcher(batch_size=3, blob_size=260)
    batch = b.flush()
    assert len(batch) == 3 and all(i.cover for i in batch)


def test_overflow_drains_across_multiple_flushes():
    b = _batcher(batch_size=2, blob_size=260)
    for i in range(3):
        b.enqueue(f"m{i}", bytes([i]) * 260)
    first, second = b.flush(), b.flush()
    assert [i.to for i in first if not i.cover] == ["m0", "m1"]
    assert [i.to for i in second if not i.cover] == ["m2"]      # 1 real + 1 cover
    assert len(second) == 2 and sum(i.cover for i in second) == 1
    assert b.pending() == 0


# ------------------------------- transport (end to end) -------------------------

def _channel(sink, batch_size=4, cell=4096):
    return PrivacyChannel(
        backend=DirectBackend(sink),
        seal=_seal,
        batch_size=batch_size,
        cover_recipient=lambda: "decoy",
        cell=cell,
        rng=_const_rng,
    )


def test_end_to_end_roundtrip_and_uniform_blob_size():
    wire = []  # what the "relay" sees: (to, blob)
    ch = _channel(lambda to, blob: wire.append((to, blob)))

    ch.send("bob", b"hello bob")
    assert ch.pending() == 1
    ch.flush()

    # relay sees a full constant-size batch; cannot tell how many were real
    assert len(wire) == 4
    assert len({len(blob) for _, blob in wire}) == 1        # all identical size
    assert all(len(blob) == ch.blob_size for _, blob in wire)

    # exactly one blob opens to the real message; the rest are cover -> None
    recovered = [PrivacyChannel.receive(blob, _open) for _, blob in wire]
    assert sorted(r for r in recovered if r is not None) == [b"hello bob"]
    assert recovered.count(None) == 3


def test_message_larger_than_cell_is_rejected_for_now():
    ch = _channel(lambda to, blob: None, cell=256)
    with pytest.raises(ValueError):
        ch.send("bob", b"x" * 256)  # exceeds the 256B cell (needs chunking, a follow-up)


def test_receive_returns_none_on_cover_or_garbage():
    assert PrivacyChannel.receive(b"\xff" * 260, _open) is None      # cover
    assert PrivacyChannel.receive(b"SEAL\x00", _open) is None        # bad frame under the tag


def test_cover_recipient_policy_is_used():
    wire = []
    ch = PrivacyChannel(
        backend=DirectBackend(lambda to, blob: wire.append(to)),
        seal=_seal,
        batch_size=3,
        cover_recipient=lambda: "mixpool",
        cell=1024,
        rng=_const_rng,
    )
    ch.send("carol", b"hi")
    ch.flush()
    assert wire.count("carol") == 1 and wire.count("mixpool") == 2


# ------------------------------- backend options --------------------------------

def test_backend_factory_returns_each_option():
    assert isinstance(make_backend("direct", send=lambda to, b: None), DirectBackend)
    assert isinstance(make_backend(BackendKind.TOR), TorBackend)
    assert isinstance(make_backend("mixnet"), MixnetBackend)
    with pytest.raises(ValueError):
        make_backend("direct")  # direct needs a send sink
    with pytest.raises(ValueError):
        make_backend("carrier-pigeon")  # unknown option


def test_tor_and_mixnet_backends_are_stubs():
    for be in (TorBackend(), MixnetBackend()):
        with pytest.raises(NotImplementedError):
            be.deliver([])
