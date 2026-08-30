"""Inheritance-gated custody (#3/#44): the custodian serves the heir share ONLY when the gate opens.

The custodian holds an opaque heir blob and cannot release it until the attorney triggers, the
time-lock elapses, and the owner did not veto — so "a lawyer holds it, released only after death and
a challenge period" is cryptographic, not trust.
"""
import pytest

from atlas.crypto.sign import generate_sig_keypair, sign
from atlas.keys.inheritance import InheritancePolicy, trigger_message, veto_message
from atlas.keys.inheritance_custody import GatedCustody, NotReleasable

GID = b"gate-id-0123456789ab"
WINDOW = 10
HEIR_BLOB = b"opaque-sealed-heir-share"


def _custody():
    owner = generate_sig_keypair()
    lawyer = generate_sig_keypair()          # the attorney / representative
    policy = InheritancePolicy(gate_id=GID, owner_pub=owner.public, trigger_pub=lawyer.public,
                               veto_window_rounds=WINDOW)
    return owner, lawyer, GatedCustody(policy=policy, heir_blob=HEIR_BLOB)


def test_armed_custodian_will_not_serve():
    _o, _l, gc = _custody()
    assert gc.status(now_round=50) == "armed"
    with pytest.raises(NotReleasable):
        gc.serve(now_round=50)


def test_inside_challenge_window_will_not_serve():
    _o, lawyer, gc = _custody()
    gc.trigger(at_round=100, signature=sign(lawyer, trigger_message(GID, 100)))
    assert gc.status(now_round=105) == "challenge"
    with pytest.raises(NotReleasable):
        gc.serve(now_round=105)


def test_serves_after_window_with_no_veto():
    _o, lawyer, gc = _custody()
    gc.trigger(at_round=100, signature=sign(lawyer, trigger_message(GID, 100)))
    assert gc.status(now_round=111) == "releasable"          # 100 + 10 elapsed
    assert gc.serve(now_round=111) == HEIR_BLOB
    # idempotent while releasable
    assert gc.serve(now_round=120) == HEIR_BLOB


def test_owner_veto_blocks_release():
    owner, lawyer, gc = _custody()
    gc.trigger(at_round=100, signature=sign(lawyer, trigger_message(GID, 100)))
    gc.veto(at_round=105, beacon_sig=b"beacon", signature=sign(owner, veto_message(GID, 105, b"beacon")))
    assert gc.status(now_round=200) == "armed"               # aborted
    with pytest.raises(NotReleasable):
        gc.serve(now_round=200)


def test_mark_released_finalizes_then_serve_fails_closed():
    _o, lawyer, gc = _custody()
    gc.trigger(at_round=100, signature=sign(lawyer, trigger_message(GID, 100)))
    assert gc.serve(now_round=111) == HEIR_BLOB
    gc.mark_released(now_round=111)
    assert gc.status(now_round=120) == "released"
    with pytest.raises(NotReleasable):
        gc.serve(now_round=120)
