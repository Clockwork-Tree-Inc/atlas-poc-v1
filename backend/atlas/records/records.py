"""Sealed records — medical + other sensitive records (assembly; nothing new cryptographically).

Composes primitives ATLAS already ships: authenticated sealing (AES-GCM), threshold splitting
(Shamir), a tamper-evident append-only access log (hash chain), and beacon-round gates (episode
window / retention expiry).

TWO privacy mechanisms exist in ATLAS and they are NOT the same — naming which carries which claim
is the point:
  * SEALED-TO-THE-PARTIES — identity is known and that's fine; the CONTENT is nobody else's business.
    Medical care is THIS kind: the clinician must know exactly who you are for care to be care. What
    makes the file private is not a pseudonym — it is that the file only opens for the patient and
    the treating clinician.
  * UNLINKABLE PERSONAS — protects IDENTITY, for reviews / votes / speech. NOT used here.

FOUR grants, each with its own lifetime (getting the lifetimes right is the whole design):
  1. PATIENT -> OWN FILE — permanent (also a legal right of access).
  2. PATIENT -> TREATING CLINICIAN — this episode only: opens for a LIVE, PRESENT clinician within
     the episode window; ENDS at discharge (re-admission simply re-grants, patient present again).
  3. CLINICIAN -> OWN ENCOUNTER NOTE — a SEPARATE object with its OWN lifetime: retained per the
     regulator (~10y in Canada), so a clinician does not lose their record at discharge.
  4. REOPEN THE RETAINED RECORD for a dispute — threshold(doctor share AND governing-body SHARE),
     PER RECORD. Never a master college key: a per-record share means a stolen body-share opens
     NOTHING on its own and the blast radius of any single failure is one record, not a province.

RETENTION != READABILITY (the genuinely novel piece): the law requires KEEPING the record, not
keeping it READABLE. The retained record stays sealed and opens ONLY on a trigger; and past the
retention end it becomes UNREADABLE — expiry as ARITHMETIC (a beacon-round gate), so "delete after
10 years" is no longer a policy someone must remember to run.

Every open — INCLUDING the patient's own — appends to a tamper-evident log; a review-unseal or a
break-glass NOTIFIES the patient (oversight in real time, not just evidence after the fact).

BREAK-GLASS (the unconscious-patient case): someone arriving by ambulance is alive and present but
cannot consent — exactly when the file is most needed. Any clinician may open, but the open is LOUD
(logged + notified + reviewable). Access is not prevented; it is made undeniable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Tuple

from ..crypto import shamir
from ..crypto.primitives import H, aead_decrypt, aead_encrypt


class RecordsError(Exception):
    """Base — fail-closed."""


class AccessDenied(RecordsError):
    """A grant's conditions were not met (discharged, outside window, not present, past retention)."""


class ThresholdNotMet(RecordsError):
    """A retained-record reopen was attempted without BOTH the doctor and the governing-body share."""


# --------------------------------------------------------------------------- append-only access log
@dataclass
class AccessEntry:
    seq: int
    who: str        # actor/role label (an opaque handle in deployment)
    action: str     # open-own | open-episode | open-note | reopen-retained | break-glass
    round: int      # beacon round of the access
    prev: bytes
    notify: bool     # True -> the patient is notified (review-unseal / break-glass)


class AccessLog:
    """Tamper-evident record of every access. Symmetric — the patient's OWN opens are logged too, so
    the trail cannot be argued with. Revocation closes FUTURE opens, never un-reads a past one; the
    log is what turns 'they promised to stop looking' into 'I can check'."""

    _ZERO = b"\x00" * 32

    def __init__(self) -> None:
        self.entries: List[AccessEntry] = []
        self.head = self._ZERO

    @staticmethod
    def _commit(who: str, action: str, round: int, notify: bool) -> bytes:
        # `notify` IS bound into the commitment — the one bit whose job is "the patient was told"
        # must not be silently flippable by an adversary holding the log.
        return H(b"atlas/records/access", who.encode(), action.encode(),
                 int(round).to_bytes(8, "big"), bytes([1 if notify else 0]))

    def record(self, *, who: str, action: str, round: int, notify: bool = False) -> AccessEntry:
        e = AccessEntry(len(self.entries), who, action, round, self.head, notify)
        self.head = H(b"atlas/records/chain", self.head, self._commit(who, action, round, notify))
        self.entries.append(e)
        return e

    def verify(self) -> bool:
        head = self._ZERO
        for e in self.entries:
            if e.prev != head:
                return False
            head = H(b"atlas/records/chain", head, self._commit(e.who, e.action, e.round, e.notify))
        return head == self.head

    def notifications(self) -> List[AccessEntry]:
        """Accesses the patient should be pushed in real time (not left to go and find)."""
        return [e for e in self.entries if e.notify]


# --------------------------------------------------------------------------- sealed record + grants
@dataclass(frozen=True)
class SealedRecord:
    """Opaque sealed content. The content_key that opens it is what the four grants control."""
    blob: bytes


def seal_record(content: bytes, content_key: bytes, *, aad: bytes = b"") -> SealedRecord:
    return SealedRecord(blob=aead_encrypt(content_key, content, aad=aad))


def _open(record: SealedRecord, content_key: bytes, aad: bytes = b"") -> bytes:
    return aead_decrypt(content_key, record.blob, aad=aad)


# 1 — PATIENT -> OWN FILE (permanent). The patient holds the content key; it always opens.
def patient_open_own(record: SealedRecord, *, content_key: bytes, log: AccessLog, now_round: int,
                     patient: str = "patient", aad: bytes = b"") -> bytes:
    log.record(who=patient, action="open-own", round=now_round)   # symmetric: even the patient's opens are logged
    return _open(record, content_key, aad=aad)


# 2 — PATIENT -> TREATING CLINICIAN (this episode only; ends at discharge; live + present + in-window)
@dataclass
class EpisodeGrant:
    wrapped_key: bytes     # aead(episode_key, content_key) — episode_key derives from the patient's grant
    opens_from: int        # beacon round the episode opened
    opens_until: int       # discharge / episode-window end
    discharged: bool = False


def clinician_open_episode(grant: EpisodeGrant, record: SealedRecord, *, episode_key: bytes,
                           now_round: int, presence_live: bool, log: AccessLog,
                           clinician: str = "clinician", aad: bytes = b"") -> bytes:
    """Opens ONLY for a live, present clinician, within the episode window, before discharge. A DENIED
    attempt is logged too — an attempted out-of-window / post-discharge / not-present open is itself
    security-relevant, so attempts and outcomes are both recorded (consistent with reopen)."""
    reason = None
    if grant.discharged:
        reason = "discharged"
    elif not (grant.opens_from <= now_round <= grant.opens_until):
        reason = "outside-window"
    elif not presence_live:
        reason = "not-present"
    if reason is not None:
        log.record(who=clinician, action=f"open-episode-denied:{reason}", round=now_round)
        raise AccessDenied(f"episode open refused ({reason})")
    content_key = aead_decrypt(episode_key, grant.wrapped_key)
    log.record(who=clinician, action="open-episode", round=now_round)
    return _open(record, content_key, aad=aad)


def discharge(grant: EpisodeGrant) -> None:
    """End the episode. The grant no longer opens; re-admission issues a fresh grant (patient present)."""
    grant.discharged = True


# 3 — CLINICIAN -> OWN ENCOUNTER NOTE (separate object; retained until retention_end, then unreadable)
def clinician_open_note(note: SealedRecord, *, note_key: bytes, now_round: int, retention_end: int,
                        log: AccessLog, clinician: str = "clinician", aad: bytes = b"") -> bytes:
    if now_round > retention_end:
        raise AccessDenied("past retention — the note is unreadable (expired by arithmetic)")
    log.record(who=clinician, action="open-note", round=now_round)
    return _open(note, note_key, aad=aad)


# 4 — REOPEN THE RETAINED RECORD for a dispute (threshold: doctor share AND governing-body SHARE)
def split_reopen_shares(content_key: bytes) -> Tuple[shamir.Share, shamir.Share]:
    """Per-record 2-of-2: the doctor's share AND the governing body's share. Independent per record,
    so a stolen body-share opens NOTHING alone and reaches exactly one record — never a province."""
    a, b = shamir.split(content_key, n=2, k=2)
    return a, b


def reopen_retained(record: SealedRecord, *, doctor_share: shamir.Share, body_share: shamir.Share,
                    now_round: int, retention_end: int, log: AccessLog, patient: str = "patient",
                    aad: bytes = b"") -> bytes:
    """A dispute reopens the retained record — needs BOTH shares, and only within retention. Logged
    and the patient is NOTIFIED (a review-unseal is not silent)."""
    if now_round > retention_end:
        raise AccessDenied("past retention — the record is unreadable (expired by arithmetic)")
    content_key = shamir.combine([doctor_share, body_share])
    try:
        plain = _open(record, content_key, aad=aad)
    except Exception as e:  # a single share (or a foreign record's share) yields the wrong key -> tag fails
        # Record the FAILED ATTEMPT — a failed reopen must not be logged as a successful one, and an
        # attempt is itself notable (someone tried). The patient is notified either way.
        log.record(who="dispute", action="reopen-retained-failed", round=now_round, notify=True)
        raise ThresholdNotMet("reopen failed — need BOTH the doctor and the governing-body share") from e
    log.record(who="dispute", action="reopen-retained", round=now_round, notify=True)
    return plain


# BREAK-GLASS — the unconscious patient. Any clinician may open; the open is LOUD (logged + notified).
def break_glass_open(record: SealedRecord, *, break_glass_key: bytes, wrapped_content_key: bytes,
                     now_round: int, log: AccessLog, clinician: str = "on-call") -> bytes:
    """Emergency open when the patient cannot consent. Not prevented — made undeniable."""
    content_key = aead_decrypt(break_glass_key, wrapped_content_key)
    log.record(who=clinician, action="break-glass", round=now_round, notify=True)
    return _open(record, content_key)
