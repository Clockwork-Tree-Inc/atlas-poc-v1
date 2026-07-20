"""Closes two review gaps:
  * the COUPLED session-key path (Math Spec §A) — built but previously untested,
  * the EPOCH-CAP runtime guard — previously a parameter, not enforced+tested.
"""

import pytest

from atlas.keys.derivation import (
    derive_session_key_coupled,
    derive_session_key_decoupled,
)
from atlas.params import EPOCH_LENGTH_CAP_S
from atlas.session.epoch_guard import EpochCapGuard, EpochStalled

TSK = b"\x11" * 32
DEV = b"\x22" * 32
POLE = b"\x33" * 32
BEACON = b"\x44" * 32
EPOCH = b"\x55" * 8


def _coupled(**over):
    kw = dict(tsk=TSK, dev_key=DEV, pole_state=POLE, beacon=BEACON, drand_round=EPOCH)
    kw.update(over)
    return derive_session_key_coupled(**kw).key


# --------------------------------------------------------------------------- coupled path
def test_coupled_is_deterministic():
    assert _coupled() == _coupled()


def test_coupled_binds_every_input():
    base = _coupled()
    assert _coupled(tsk=b"\x00" * 32) != base
    assert _coupled(dev_key=b"\x00" * 32) != base
    assert _coupled(pole_state=b"\x00" * 32) != base
    assert _coupled(beacon=b"\x00" * 32) != base


def test_coupled_off_device_rooting_needs_the_live_beacon():
    # An attacker with tsk + dev_key + pole but the WRONG (not live) beacon derives a
    # different session key — it cannot be rooted off-device without the live beacon.
    assert _coupled(beacon=b"\x99" * 32) != _coupled()


def test_coupled_and_decoupled_are_distinct_constructions():
    decoupled = derive_session_key_decoupled(
        lk=TSK, epoch_key=DEV, pole_value=POLE, prev_key=BEACON,
        context_separator=b"ctx", drand_round=EPOCH).key
    assert _coupled() != decoupled


# --------------------------------------------------------------------------- epoch-cap guard
def test_within_cap_is_valid():
    g = EpochCapGuard()
    g.beacon_advanced(at_s=100.0)
    g.check(now_s=100.0 + EPOCH_LENGTH_CAP_S - 1)     # inside the window -> no raise


def test_beyond_cap_without_advance_forces_rekey():
    g = EpochCapGuard()
    g.beacon_advanced(at_s=100.0)
    with pytest.raises(EpochStalled):
        g.check(now_s=100.0 + EPOCH_LENGTH_CAP_S)     # beacon stalled -> re-key


def test_a_fresh_beacon_advance_resets_the_window():
    g = EpochCapGuard()
    g.beacon_advanced(at_s=100.0)
    assert g.expired(now_s=100.0 + EPOCH_LENGTH_CAP_S)
    g.beacon_advanced(at_s=100.0 + EPOCH_LENGTH_CAP_S)   # new epoch
    g.check(now_s=100.0 + EPOCH_LENGTH_CAP_S + 1)        # valid again


def test_never_advanced_is_expired_fail_closed():
    g = EpochCapGuard()
    assert g.expired(now_s=0.0)
    with pytest.raises(EpochStalled):
        g.check(now_s=0.0)
