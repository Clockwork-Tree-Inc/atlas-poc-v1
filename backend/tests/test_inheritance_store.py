"""Persisted, beacon-verified inheritance-gated custody (#3/#44).

Beyond the gate logic, this asserts the two properties the NODE needs:
  * STATE SURVIVES A RESTART — a fired trigger is not reset by reloading the store (an attacker
    rebooting the custodian cannot reopen the challenge);
  * A FORGED BEACON SIGNATURE IS REJECTED — a veto whose freshness signature isn't drand's genuine
    signature for the round does not abort the gate.
"""
import pytest

from atlas.crypto.sign import generate_sig_keypair, sign
from atlas.keys.inheritance import trigger_message, veto_message
from atlas.keys.inheritance_store import BeaconUnverified, InheritanceStore, NotReleasable

GID = b"gate-id-0123456789ab"
WINDOW = 10
HEIR = b"opaque-heir-share"
LOC = "abc123"


class Clock:
    def __init__(self, t): self.t = t
    def __call__(self): return self.t


def _store(tmp_path, clock, verify_ok=True):
    return InheritanceStore(str(tmp_path), current_round=clock,
                            verify_round=lambda r, s: verify_ok)


def _arm(store, owner, lawyer):
    store.arm(locator=LOC, heir_blob=HEIR, gate_id=GID,
              owner_pub=owner.public, trigger_pub=lawyer.public, veto_window_rounds=WINDOW)


def test_arm_persist_and_serve_flow(tmp_path):
    owner, lawyer = generate_sig_keypair(), generate_sig_keypair()
    clock = Clock(50)
    store = _store(tmp_path, clock)
    _arm(store, owner, lawyer)
    assert store.status(locator=LOC) == "armed"
    with pytest.raises(NotReleasable):
        store.serve(locator=LOC)

    clock.t = 100
    store.trigger(locator=LOC, at_round=100, signature=sign(lawyer, trigger_message(GID, 100)))
    clock.t = 105
    assert store.status(locator=LOC) == "challenge"
    with pytest.raises(NotReleasable):
        store.serve(locator=LOC)
    clock.t = 111
    assert store.serve(locator=LOC) == HEIR                 # window elapsed, no veto


def test_state_survives_restart(tmp_path):
    owner, lawyer = generate_sig_keypair(), generate_sig_keypair()
    clock = Clock(100)
    _store(tmp_path, clock).arm(locator=LOC, heir_blob=HEIR, gate_id=GID,
                                owner_pub=owner.public, trigger_pub=lawyer.public,
                                veto_window_rounds=WINDOW)
    _store(tmp_path, clock).trigger(locator=LOC, at_round=100,
                                    signature=sign(lawyer, trigger_message(GID, 100)))
    # a brand-new store on the same dir (i.e. a restart) MUST see the fired trigger — no reset
    fresh = _store(tmp_path, clock)
    clock.t = 111
    assert fresh.status(locator=LOC) == "releasable"
    assert fresh.serve(locator=LOC) == HEIR


def test_genuine_veto_aborts(tmp_path):
    owner, lawyer = generate_sig_keypair(), generate_sig_keypair()
    clock = Clock(100)
    store = _store(tmp_path, clock, verify_ok=True)
    _arm(store, owner, lawyer)
    store.trigger(locator=LOC, at_round=100, signature=sign(lawyer, trigger_message(GID, 100)))
    store.veto(locator=LOC, at_round=105, beacon_sig=b"genuine",
               signature=sign(owner, veto_message(GID, 105, b"genuine")))
    clock.t = 200
    assert store.status(locator=LOC) == "armed"             # aborted
    with pytest.raises(NotReleasable):
        store.serve(locator=LOC)


def test_forged_beacon_sig_is_rejected_and_does_not_abort(tmp_path):
    owner, lawyer = generate_sig_keypair(), generate_sig_keypair()
    clock = Clock(100)
    store = _store(tmp_path, clock, verify_ok=False)        # the node says: not drand's real sig
    _arm(store, owner, lawyer)
    store.trigger(locator=LOC, at_round=100, signature=sign(lawyer, trigger_message(GID, 100)))
    with pytest.raises(BeaconUnverified):
        store.veto(locator=LOC, at_round=105, beacon_sig=b"forged",
                   signature=sign(owner, veto_message(GID, 105, b"forged")))
    clock.t = 111
    assert store.serve(locator=LOC) == HEIR                 # forged veto never took effect


def test_arm_refuses_to_clobber(tmp_path):
    owner, lawyer = generate_sig_keypair(), generate_sig_keypair()
    store = _store(tmp_path, Clock(50))
    _arm(store, owner, lawyer)
    with pytest.raises(ValueError):
        _arm(store, owner, lawyer)
