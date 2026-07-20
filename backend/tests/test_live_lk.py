"""Two-device co-derived live LK: unpredictable-to-either, controllable-by-neither."""

import pytest

from atlas.session.live_lk import co_derive_lk, device_contribution


def test_both_devices_derive_the_same_lk_regardless_of_order():
    a, b = device_contribution(), device_contribution()
    epoch = b"\x00" * 8
    lk_from_a_view = co_derive_lk([a, b], drand_round=epoch)   # A holds [a, b]
    lk_from_b_view = co_derive_lk([b, a], drand_round=epoch)   # B holds [b, a]
    assert lk_from_a_view == lk_from_b_view                 # order-independent -> same LK
    assert len(lk_from_a_view) == 32


def test_neither_contribution_equals_or_reveals_the_lk():
    a, b = device_contribution(), device_contribution()
    lk = co_derive_lk([a, b], drand_round=b"\x00" * 8)
    assert lk != a and lk != b                              # controllable-by-neither
    # one party swapping its own contribution changes the LK -> neither pins it alone
    a2 = device_contribution()
    assert co_derive_lk([a2, b], drand_round=b"\x00" * 8) != lk


def test_lk_is_epoch_bound():
    a, b = device_contribution(), device_contribution()
    assert co_derive_lk([a, b], drand_round=b"\x00" * 8) != co_derive_lk([a, b], drand_round=b"\x01" * 8)


def test_single_contribution_is_refused():
    with pytest.raises(ValueError):
        co_derive_lk([device_contribution()], drand_round=b"\x00" * 8)
