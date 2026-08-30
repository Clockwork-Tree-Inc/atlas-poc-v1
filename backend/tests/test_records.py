"""Sealed records assembly (#46 / handoff PART 3): four grants with distinct lifetimes, threshold
reopen, retention-as-arithmetic, break-glass, and a symmetric tamper-evident access log."""
import pytest

from atlas.crypto import shamir
from atlas.crypto.primitives import aead_encrypt, random_bytes
from atlas.records import (AccessDenied, AccessLog, EpisodeGrant, ThresholdNotMet, break_glass_open,
                           clinician_open_episode, clinician_open_note, discharge, patient_open_own,
                           reopen_retained, seal_record, split_reopen_shares)

FILE = b"Dx: hypertension. anticoagulant: warfarin. allergy: penicillin."


def _sealed():
    ck = random_bytes(32)
    return seal_record(FILE, ck), ck


def test_patient_opens_own_file_anytime_and_it_is_logged():
    rec, ck = _sealed()
    log = AccessLog()
    assert patient_open_own(rec, content_key=ck, log=log, now_round=1_000) == FILE
    assert log.entries[0].action == "open-own" and not log.entries[0].notify   # own access, no self-notify


def test_treating_clinician_only_within_episode_present_and_before_discharge():
    rec, ck = _sealed()
    log = AccessLog()
    ek = random_bytes(32)
    grant = EpisodeGrant(wrapped_key=aead_encrypt(ek, ck), opens_from=100, opens_until=200)

    # live + present + in-window -> opens
    assert clinician_open_episode(grant, rec, episode_key=ek, now_round=150,
                                  presence_live=True, log=log) == FILE
    # not present -> denied
    with pytest.raises(AccessDenied):
        clinician_open_episode(grant, rec, episode_key=ek, now_round=150, presence_live=False, log=log)
    # outside the window -> denied
    with pytest.raises(AccessDenied):
        clinician_open_episode(grant, rec, episode_key=ek, now_round=250, presence_live=True, log=log)
    # discharge ends it
    discharge(grant)
    with pytest.raises(AccessDenied):
        clinician_open_episode(grant, rec, episode_key=ek, now_round=150, presence_live=True, log=log)


def test_clinician_note_retained_then_unreadable_past_retention():
    note, nk = _sealed()
    log = AccessLog()
    assert clinician_open_note(note, note_key=nk, now_round=5_000, retention_end=10_000, log=log) == FILE
    with pytest.raises(AccessDenied):        # past the retention end -> unreadable by arithmetic
        clinician_open_note(note, note_key=nk, now_round=10_001, retention_end=10_000, log=log)


def test_reopen_needs_both_shares_and_notifies_and_is_per_record():
    rec, ck = _sealed()
    log = AccessLog()
    doctor, body = split_reopen_shares(ck)

    # both shares within retention -> opens, and the patient is notified
    assert reopen_retained(rec, doctor_share=doctor, body_share=body,
                           now_round=5_000, retention_end=10_000, log=log) == FILE
    assert log.entries[-1].action == "reopen-retained" and log.entries[-1].notify

    # a governing-body share from a DIFFERENT record cannot open this one (per-record, not a master key)
    _, other_body = split_reopen_shares(random_bytes(32))
    with pytest.raises(ThresholdNotMet):
        reopen_retained(rec, doctor_share=doctor, body_share=other_body,
                        now_round=5_000, retention_end=10_000, log=AccessLog())

    # past retention -> unreadable even WITH both shares
    with pytest.raises(AccessDenied):
        reopen_retained(rec, doctor_share=doctor, body_share=body,
                        now_round=10_001, retention_end=10_000, log=AccessLog())


def test_one_share_alone_cannot_reopen():
    rec, ck = _sealed()
    doctor, _body = split_reopen_shares(ck)
    # a single Shamir share can't even be combined (k=2) -> reopen fails closed
    with pytest.raises(Exception):
        reopen_retained(rec, doctor_share=doctor, body_share=doctor,
                        now_round=1, retention_end=10_000, log=AccessLog())


def test_break_glass_opens_but_is_loud():
    rec, ck = _sealed()
    log = AccessLog()
    bg = random_bytes(32)
    assert break_glass_open(rec, break_glass_key=bg, wrapped_content_key=aead_encrypt(bg, ck),
                            now_round=42, log=log) == FILE
    e = log.entries[-1]
    assert e.action == "break-glass" and e.notify        # never silent


def test_access_log_is_symmetric_and_tamper_evident():
    rec, ck = _sealed()
    log = AccessLog()
    patient_open_own(rec, content_key=ck, log=log, now_round=1)
    doctor, body = split_reopen_shares(ck)
    reopen_retained(rec, doctor_share=doctor, body_share=body, now_round=2, retention_end=99, log=log)
    assert log.verify()
    assert [e.action for e in log.notifications()] == ["reopen-retained"]   # only the review-unseal notifies
    # tamper: rewrite an entry -> chain no longer verifies
    log.entries[0].action = "forged"
    assert not log.verify()
