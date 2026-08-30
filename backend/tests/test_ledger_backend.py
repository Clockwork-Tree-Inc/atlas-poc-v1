"""Pluggable ledger anchor backend: local now, PoLE-consensus chain later — same interface."""
import pytest

from atlas.ledger.backend import ChainBackend, LocalBackend


def _r(n: int) -> bytes:
    return n.to_bytes(8, "big")


def test_local_backend_publishes_and_reads_latest():
    b = LocalBackend()
    root = b"\x11" * 32
    b.publish(b"owner:econ", root, _r(1))
    assert b.latest(b"owner:econ") == root
    assert b.latest(b"owner:none") is None


def test_local_backend_rejects_backdated_round():
    b = LocalBackend()
    b.publish(b"o", b"\x01" * 32, _r(5))
    with pytest.raises(ValueError):
        b.publish(b"o", b"\x02" * 32, _r(4))   # non-monotonic drand round


def test_chain_backend_is_a_stub():
    with pytest.raises(NotImplementedError):
        ChainBackend().publish(b"o", b"\x00" * 32, _r(1))


def test_backends_share_interface():
    for be in (LocalBackend(), ChainBackend()):
        assert hasattr(be, "publish") and hasattr(be, "latest")
