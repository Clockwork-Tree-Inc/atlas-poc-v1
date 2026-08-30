"""ML-KEM backend safety (security review #7): the pure-Python kyber-py reference is NOT
constant-time, so a publicly-reachable node that decapsulates must FAIL CLOSED rather than run a
timing-leaky decapsulation. With liboqs installed (hosted nodes) the constant-time backend is
active and the guard passes; without it (dev/LAN/tests) the guard refuses public exposure."""

import pytest

from atlas.crypto import kem


def test_backend_flag_matches_active_backend():
    if kem.KEM_BACKEND == "liboqs":
        assert kem.KEM_CONSTANT_TIME is True
    else:
        assert kem.KEM_BACKEND == "reference-kyber-py"
        assert kem.KEM_CONSTANT_TIME is False


def test_guard_fails_closed_on_reference_passes_on_liboqs():
    if kem.KEM_CONSTANT_TIME:
        kem.require_constant_time_kem()      # native backend: public exposure permitted
    else:
        # A hosted/publicly-reachable node calls this at startup; with only the reference
        # backend it must refuse to run (so the leaky impl can never be deployed reachable).
        with pytest.raises(kem.InsecureKEMBackend):
            kem.require_constant_time_kem()


def test_kem_roundtrip_on_active_backend():
    kp = kem.generate_keypair()
    enc = kem.encapsulate(kp.public)
    assert kem.decapsulate(kp, enc.mlkem_ct, enc.x25519_eph_pk) == enc.shared