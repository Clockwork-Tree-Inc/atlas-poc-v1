"""The ONE principle (Locked Model §2.3): value = QRNG (clean); timing/liveness
times draws and gates operations but NEVER enters a value or KDF.

Covers the value/timing conformance fixes #11, #15, #19, #23 at the unit level;
the epoch-wraps-LK chain (#15) is exercised end-to-end in
test_session::test_no_continuity_no_epoch_key_no_lk_no_ratchet, and the clean-LK-
value (#23) in test_security_properties + threat-model T-04.
"""

import inspect
import os

from atlas.keys.derivation import derive_session_key_decoupled
from atlas.session.pole import fire_pole_value
from atlas.session.presence import wrap_lk, unlock_lk


# -- #11: session key = KDF(PoLE_value, LK, epoch_key, prev_key, ctx) --------

def test_session_kdf_inputs_are_exactly_the_locked_model_set():
    """No continuity_flag, no un-timed local_qrng_draw, no drand — the KDF inputs
    are exactly {PoLE_value, LK, epoch_key, prev_key, ctx} (+ drand_round label)."""
    params = set(inspect.signature(derive_session_key_decoupled).parameters)
    assert params == {"lk", "epoch_key", "pole_value", "prev_key",
                      "context_separator", "drand_round"}
    assert "continuity_flag" not in params          # continuity gates upstream, not an input
    assert "local_qrng_draw" not in params          # replaced by the physio-timed PoLE_value


def test_pole_value_changes_the_session_key():
    common = dict(lk=b"L" * 32, epoch_key=b"E" * 32, prev_key=b"\x00" * 32,
                  context_separator=b"tunnel", drand_round=b"\x00" * 8)
    a = derive_session_key_decoupled(pole_value=b"\x01" * 32, **common).key
    b = derive_session_key_decoupled(pole_value=b"\x02" * 32, **common).key
    assert a != b


# -- #23 / PoLE: PoLE_value is a physiologically-TIMED CLEAN QRNG value -------

def test_pole_value_is_clean_qrng_timing_does_not_enter_it():
    """PoLE_value is a clean QRNG draw. The physiological FIRE MOMENT only times
    WHEN it fires; it must not determine the bytes. So the value is unpredictable
    and independent of the fire-moment argument."""
    v1 = fire_pole_value(physio_fire_moment=0.10)
    v2 = fire_pole_value(physio_fire_moment=0.90)
    v3 = fire_pole_value(physio_fire_moment=0.10)   # same moment again
    assert len(v1) == 32
    # clean QRNG: distinct draws (even at the SAME fire moment) -> not a function
    # of the timing; the timing did not seed the value.
    assert v1 != v2 != v3 and v1 != v3


# -- #15: the (public) epoch key wraps/unlocks the (private) LK ---------------

def test_epoch_key_wraps_and_unlocks_the_lk():
    lk, ek, eid = os.urandom(32), os.urandom(32), b"\x00" * 8
    wrapped = wrap_lk(lk, epoch_key=ek, drand_round=eid)
    assert wrapped != lk                                  # LK is not in the clear
    assert unlock_lk(wrapped, epoch_key=ek, drand_round=eid) == lk
    # wrong epoch key cannot unlock the LK (no epoch key -> no LK)
    import pytest
    with pytest.raises(Exception):
        unlock_lk(wrapped, epoch_key=os.urandom(32), drand_round=eid)
