"""Inheritance gate — death-trigger ∧ liveness-veto (groundwork for #44; ancestor-AI is separate).

Release the heir's share ONLY if the executor fires a trigger AND the owner fails to prove liveness
within the beacon-clocked challenge window. Being alive always vetoes."""
import pytest

from atlas.crypto.sign import generate_sig_keypair, sign
from atlas.keys.inheritance import (BadAuthority, GateState, InheritancePolicy, NotTriggered,
                                     WindowElapsed, apply_trigger, apply_veto, can_release,
                                     mark_released, status, trigger_message, veto_message)

GID = b"gate-id-0123456789ab"       # >= 16 bytes
WINDOW = 10


def _setup():
    owner = generate_sig_keypair()
    lawyer = generate_sig_keypair()
    pol = InheritancePolicy(gate_id=GID, owner_pub=owner.public, trigger_pub=lawyer.public,
                            veto_window_rounds=WINDOW)
    return owner, lawyer, pol


def _trigger(pol, lawyer, state, at):
    return apply_trigger(pol, state, at_round=at, signature=sign(lawyer, trigger_message(GID, at)))


def _veto(pol, owner, state, at, beacon_sig=b"beacon-sig"):
    sig = sign(owner, veto_message(GID, at, beacon_sig))
    return apply_veto(pol, state, at_round=at, beacon_sig=beacon_sig, signature=sig)


def test_release_after_window_with_no_veto():
    _o, lawyer, pol = _setup()
    st = GateState()
    assert status(pol, st, now_round=50) == "armed"
    _trigger(pol, lawyer, st, 100)
    assert status(pol, st, now_round=105) == "challenge"      # inside the window
    assert not can_release(pol, st, now_round=105)
    assert status(pol, st, now_round=111) == "releasable"     # window elapsed (100 + 10)
    mark_released(pol, st, now_round=111)
    assert st.released and status(pol, st, now_round=111) == "released"


def test_liveness_veto_aborts_the_trigger():
    owner, lawyer, pol = _setup()
    st = GateState()
    _trigger(pol, lawyer, st, 100)
    _veto(pol, owner, st, 105)                                # owner proves alive within window
    assert st.veto_count == 1 and st.triggered_at is None
    assert status(pol, st, now_round=111) == "armed"          # back to armed — no release
    assert not can_release(pol, st, now_round=111)
    with pytest.raises(Exception):
        mark_released(pol, st, now_round=111)


def test_veto_after_window_is_rejected():
    owner, lawyer, pol = _setup()
    st = GateState()
    _trigger(pol, lawyer, st, 100)
    with pytest.raises(WindowElapsed):
        _veto(pol, owner, st, 111)                            # 111 > 100 + 10


def test_unauthorized_trigger_and_veto_fail_closed():
    owner, lawyer, pol = _setup()
    st = GateState()
    # owner's key cannot fire a trigger
    with pytest.raises(BadAuthority):
        apply_trigger(pol, st, at_round=100, signature=sign(owner, trigger_message(GID, 100)))
    # lawyer's key cannot veto
    _trigger(pol, lawyer, st, 100)
    with pytest.raises(BadAuthority):
        apply_veto(pol, st, at_round=105, beacon_sig=b"x",
                   signature=sign(lawyer, veto_message(GID, 105, b"x")))


def test_veto_without_trigger_is_noop_error():
    owner, _lawyer, pol = _setup()
    with pytest.raises(NotTriggered):
        _veto(pol, owner, GateState(), 105)


def test_owner_can_be_vetoed_then_actually_die_later():
    """Owner vetoes a premature trigger; later a real trigger with no veto releases."""
    owner, lawyer, pol = _setup()
    st = GateState()
    _trigger(pol, lawyer, st, 100)
    _veto(pol, owner, st, 103)                                # alive — aborts
    _trigger(pol, lawyer, st, 200)                            # later, executor tries again
    assert can_release(pol, st, now_round=211)                # no veto this time -> releases
    mark_released(pol, st, now_round=211)
    assert st.released
