"""Per-decision forensic ledger: every decision is recorded, the chain is tamper-evident
and signed, the log is opaque at rest, and suspicious signals escalate."""

import dataclasses

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from atlas.crypto.primitives import random_bytes
from atlas.session.forensic_ledger import (
    DecisionType,
    ForensicLedger,
    Outcome,
    RiskLevel,
    Signals,
    assess_risk,
    decide_and_record,
)


def _ledger():
    return ForensicLedger(Ed25519PrivateKey.generate(), random_bytes(32))


def _handle():
    return random_bytes(16)


# --------------------------------------------------------------------------- risk model
def test_calm_known_present_is_routine_and_allows():
    d = decide_and_record(_ledger(), decision=DecisionType.LOGIN, drand_round=b"e0",
                          context_handle=_handle(), signals=Signals())
    assert d.risk is RiskLevel.ROUTINE and d.outcome is Outcome.ALLOW


def test_suspicious_signals_escalate():
    for sig in [
        Signals(sudden_liveness_loss=True),                 # sudden liveness loss
        Signals(known_device=False),                        # strange login: new device
        Signals(impossible_travel=True),                    # geovelocity anomaly
        Signals(recent_failures=3),                         # repeated failed factors
    ]:
        assert assess_risk(sig) is RiskLevel.SUSPICIOUS
        d = decide_and_record(_ledger(), decision=DecisionType.LOGIN, drand_round=b"e",
                              context_handle=_handle(), signals=sig)
        assert d.outcome is Outcome.ESCALATE


def test_duress_and_total_loss_outrank():
    assert assess_risk(Signals(duress=True)) is RiskLevel.DURESS
    assert assess_risk(Signals(total_loss=True)) is RiskLevel.EMERGENCY
    # duress outranks even total loss
    assert assess_risk(Signals(duress=True, total_loss=True)) is RiskLevel.DURESS


def test_failed_factors_are_denied_regardless_of_risk():
    d = decide_and_record(_ledger(), decision=DecisionType.HIGH_STAKES, drand_round=b"e",
                          context_handle=_handle(), signals=Signals(factors_ok=False))
    assert d.outcome is Outcome.DENY


# --------------------------------------------------------------------------- every decision recorded
def test_every_decision_leaves_exactly_one_event():
    ledger = _ledger()
    for i, sig in enumerate([Signals(), Signals(factors_ok=False),
                             Signals(sudden_liveness_loss=True), Signals(duress=True)]):
        decide_and_record(ledger, decision=DecisionType.LOGIN, drand_round=f"e{i}".encode(),
                          context_handle=_handle(), signals=sig)
    assert len(ledger.entries) == 4          # allow, deny, escalate, escalate all recorded
    assert ledger.verify()


# --------------------------------------------------------------------------- tamper-evidence
def test_altering_a_sealed_event_breaks_the_chain():
    ledger = _ledger()
    for i in range(3):
        decide_and_record(ledger, decision=DecisionType.LOGIN, drand_round=f"e{i}".encode(),
                          context_handle=_handle(), signals=Signals())
    assert ledger.verify()
    tampered = bytearray(ledger.entries[1].sealed); tampered[-1] ^= 0x01
    ledger.entries[1] = dataclasses.replace(ledger.entries[1], sealed=bytes(tampered))
    assert not ledger.verify()               # sealed content no longer hashes to event_hash


def test_dropping_an_event_breaks_the_chain():
    ledger = _ledger()
    for i in range(3):
        decide_and_record(ledger, decision=DecisionType.LOGIN, drand_round=f"e{i}".encode(),
                          context_handle=_handle(), signals=Signals())
    del ledger.entries[1]                     # drop the middle event
    assert not ledger.verify()                # prev_hash chain no longer links


def test_reordering_events_breaks_the_chain():
    ledger = _ledger()
    for i in range(3):
        decide_and_record(ledger, decision=DecisionType.LOGIN, drand_round=f"e{i}".encode(),
                          context_handle=_handle(), signals=Signals())
    ledger.entries[0], ledger.entries[1] = ledger.entries[1], ledger.entries[0]
    assert not ledger.verify()


def test_forged_event_from_another_device_fails_verify():
    ledger = _ledger()
    decide_and_record(ledger, decision=DecisionType.LOGIN, drand_round=b"e0",
                      context_handle=_handle(), signals=Signals())
    other_device = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    assert not ledger.verify(device_public=other_device)


# --------------------------------------------------------------------------- opaque at rest
def test_ledger_is_opaque_at_rest():
    ledger = _ledger()
    handle = _handle()
    decide_and_record(ledger, decision=DecisionType.PAYMENT, drand_round=b"e0",
                      context_handle=handle, signals=Signals())
    # the subject handle is not readable in the sealed row
    assert handle not in ledger.entries[0].sealed
