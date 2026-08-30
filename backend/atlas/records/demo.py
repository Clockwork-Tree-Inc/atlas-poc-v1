"""A ~10-second, self-evident demo of the sealed-records assembly. Run:

    python -m atlas.records.demo

Shows the four grants and their lifetimes, retention-as-arithmetic, a dispute reopen needing BOTH
shares, break-glass, and the symmetric tamper-evident access log — using only shipped primitives.
"""
from __future__ import annotations

from ..crypto.primitives import aead_encrypt, random_bytes
from .records import (AccessDenied, AccessLog, EpisodeGrant, ThresholdNotMet, break_glass_open,
                      clinician_open_episode, clinician_open_note, discharge, patient_open_own,
                      reopen_retained, seal_record, split_reopen_shares)

FILE = b"Dx: hypertension. anticoagulant: warfarin. allergy: penicillin."


def run_demo() -> None:
    log = AccessLog()
    content_key = random_bytes(32)
    record = seal_record(FILE, content_key)
    print("sealed the patient file — opaque to everyone without a grant\n")

    # 1. patient -> own file (permanent)
    print("1. PATIENT opens own file:", patient_open_own(record, content_key=content_key,
                                                          log=log, now_round=1).decode())

    # 2. patient -> treating clinician (this episode; presence-gated; ends at discharge)
    ek = random_bytes(32)
    grant = EpisodeGrant(wrapped_key=aead_encrypt(ek, content_key), opens_from=100, opens_until=200)
    print("2. CLINICIAN (live, in-episode) opens:",
          clinician_open_episode(grant, record, episode_key=ek, now_round=150,
                                 presence_live=True, log=log).decode())
    discharge(grant)
    try:
        clinician_open_episode(grant, record, episode_key=ek, now_round=150, presence_live=True, log=log)
    except AccessDenied as e:
        print("   after DISCHARGE, same clinician:", f"REFUSED ({e})")

    # 3. clinician -> own note (retained, then unreadable by arithmetic)
    note_key = random_bytes(32)
    note = seal_record(b"encounter note: BP 150/95, adjusted dose.", note_key)
    print("3. CLINICIAN note during retention:",
          clinician_open_note(note, note_key=note_key, now_round=5_000, retention_end=10_000, log=log).decode())
    try:
        clinician_open_note(note, note_key=note_key, now_round=10_001, retention_end=10_000, log=log)
    except AccessDenied as e:
        print("   PAST retention:", f"UNREADABLE ({e})")

    # 4. dispute reopen — needs BOTH shares (doctor AND governing body), per record
    doctor, body = split_reopen_shares(content_key)
    try:
        reopen_retained(record, doctor_share=doctor, body_share=doctor,
                        now_round=6_000, retention_end=10_000, log=AccessLog())
    except (ThresholdNotMet, Exception):
        print("4. DISPUTE reopen with only the doctor's share: REFUSED (need the body's share too)")
    print("   with BOTH shares:",
          reopen_retained(record, doctor_share=doctor, body_share=body,
                          now_round=6_000, retention_end=10_000, log=log).decode(), "(patient NOTIFIED)")

    # break-glass — unconscious patient
    bg = random_bytes(32)
    print("5. BREAK-GLASS (unconscious patient):",
          break_glass_open(record, break_glass_key=bg, wrapped_content_key=aead_encrypt(bg, content_key),
                           now_round=7_000, log=log).decode(), "(logged + patient NOTIFIED)")

    print("\naccess log verifies:", log.verify(), "| entries:", len(log.entries),
          "| patient notifications:", [e.action for e in log.notifications()])


if __name__ == "__main__":
    run_demo()
