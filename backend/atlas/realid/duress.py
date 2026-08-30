"""Behavioural duress channel (Real-ID spec §7, threat T-7).

A canary finger and/or a duress tap/ending-pattern that looks identical to a
normal action to an observer but silently signals coercion. When triggered, the
system presents a plausible-looking success to the observer while internally
flagging coercion and withholding the sensitive action (e.g. does NOT surface L2,
does NOT authorize high-value).

No observable difference: the duress path is externally indistinguishable from
the normal path (same surface response, constant-time comparisons), while
internally diverging. Secrets are stored only as hashes (reuse enclave-secret
handling), never transmitted.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Optional

from ..crypto.primitives import H, random_bytes


@dataclass
class DuressEnrolment:
    """Registered at (test) enrolment. Stores only salted hashes."""

    _salt: bytes
    _normal_hash: bytes
    _duress_hash: bytes
    _canary_finger: int   # index of the designated canary finger

    @staticmethod
    def enrol(*, normal_pattern: bytes, duress_pattern: bytes, canary_finger: int) -> "DuressEnrolment":
        salt = random_bytes(16)
        return DuressEnrolment(
            _salt=salt,
            _normal_hash=H(b"atlas/duress", salt, normal_pattern),
            _duress_hash=H(b"atlas/duress", salt, duress_pattern),
            _canary_finger=canary_finger,
        )

    def _matches(self, pattern: bytes, which: bytes) -> bool:
        return hmac.compare_digest(H(b"atlas/duress", self._salt, pattern), which)


@dataclass(frozen=True)
class AuthOutcome:
    """What the OBSERVER sees vs. what the system does internally."""

    surface_success: bool     # what an observer/coercer sees (identical both paths)
    duress: bool              # internal only — never surfaced
    sensitive_action_allowed: bool


def authenticate(enr: DuressEnrolment, *, pattern: bytes, finger: int,
                 sensitive: bool = True) -> AuthOutcome:
    """Authenticate with an ending pattern + finger.

    Normal pattern + non-canary finger -> success, sensitive action allowed.
    Duress pattern OR canary finger     -> looks identical (surface_success=True)
                                           but internally flags duress and
                                           WITHHOLDS the sensitive action.
    Anything else -> a plain failure.
    """
    is_normal = enr._matches(pattern, enr._normal_hash)
    is_duress = enr._matches(pattern, enr._duress_hash)
    is_canary = (finger == enr._canary_finger)

    if not (is_normal or is_duress):
        # genuine wrong pattern — ordinary failure (distinct from duress).
        return AuthOutcome(surface_success=False, duress=False, sensitive_action_allowed=False)

    duress = is_duress or is_canary
    # Surface response is identical whether or not duress fired; only the
    # internal flag and the sensitive-action gate diverge.
    return AuthOutcome(
        surface_success=True,
        duress=duress,
        sensitive_action_allowed=(not duress) if sensitive else True,
    )
