"""Sensitive space — a records-backed space at the HIGH-PROTECTION tier, unifying the two layers we
built separately. A "sensitive record" is just a space whose policy is strict:

  * the SPACE POLICY (spaces.space_policy) decides WHO may act and at what ROLE — reader / contributor
    / governor / break-glass — with a tamper-evident, quorum-governed access set.
  * the RECORDS layer (records.records) decides WHEN and HOW the content actually opens — episode
    windows, retention arithmetic, break-glass loudness, threshold reopen.

Both must pass: role-gates WHO, records-gates WHEN. Defense in depth — a member with the right role
still can't open a retention-expired record; a valid records key still can't be used by a non-member.
This is the "records/witness/vault = a space at the sensitive tier" fold, as a thin composition (no
new crypto). Reference of record. Swift parity: ios/.../Spaces/SensitiveSpace.swift.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..crypto.sign import HybridSigPublic
from ..records import records as R
from .space_policy import Role, SpacePolicy


class SensitiveSpaceError(Exception):
    """A member lacked the required space-policy ROLE for the action (the records-layer conditions are
    checked separately and raise their own errors)."""


@dataclass
class SensitiveSpace:
    policy: SpacePolicy          # WHO may act (roles + quorum governance + audit)
    record: R.SealedRecord       # the sealed content
    log: R.AccessLog             # the records access log (symmetric, tamper-evident)


def _require(space: SensitiveSpace, member: HybridSigPublic, role: Role, what: str) -> None:
    if not space.policy.can(member, role):
        raise SensitiveSpaceError(f"member lacks the {role.name} role required to {what}")


def open_own(space: SensitiveSpace, member: HybridSigPublic, *, content_key: bytes, now_round: int,
             aad: bytes = b"") -> bytes:
    """A READER+ member opens the record; every open is logged (symmetric trail)."""
    _require(space, member, Role.READER, "read this space")
    who = member.encode().hex()[:16]
    return R.patient_open_own(space.record, content_key=content_key, log=space.log,
                              now_round=now_round, patient=who, aad=aad)


def open_episode(space: SensitiveSpace, member: HybridSigPublic, grant: R.EpisodeGrant, *,
                 episode_key: bytes, now_round: int, presence_live: bool, aad: bytes = b"") -> bytes:
    """A CONTRIBUTOR+ member (e.g. a treating clinician added to the space) opens within the episode —
    role-gated AND records-gated (live, present, in-window, before discharge)."""
    _require(space, member, Role.CONTRIBUTOR, "open the episode")
    who = member.encode().hex()[:16]
    return R.clinician_open_episode(grant, space.record, episode_key=episode_key, now_round=now_round,
                                    presence_live=presence_live, log=space.log, clinician=who, aad=aad)


def break_glass(space: SensitiveSpace, member: HybridSigPublic, *, break_glass_key: bytes,
                wrapped_content_key: bytes, now_round: int) -> bytes:
    """Only a BREAK_GLASS-role holder may emergency-open; the open is loud (logged + notified)."""
    _require(space, member, Role.BREAK_GLASS, "break the glass")
    who = member.encode().hex()[:16]
    return R.break_glass_open(space.record, break_glass_key=break_glass_key,
                              wrapped_content_key=wrapped_content_key, now_round=now_round,
                              log=space.log, clinician=who)


def reopen_dispute(space: SensitiveSpace, *, doctor_share, body_share, now_round: int,
                   retention_end: int, aad: bytes = b"") -> bytes:
    """Reopen the retained record — the GOVERNOR quorum is what authorized handing out the body-share
    (space-policy side); here the records threshold (doctor AND body share, within retention) is the
    arithmetic gate. Logged + patient-notified."""
    return R.reopen_retained(space.record, doctor_share=doctor_share, body_share=body_share,
                             now_round=now_round, retention_end=retention_end, log=space.log, aad=aad)
