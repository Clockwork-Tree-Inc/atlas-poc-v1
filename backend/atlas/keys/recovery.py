"""Threshold recovery — STRATIFIED by release mechanism (§7.2, §7.3).

The TSK seed is split 2-of-3 (Shamir) into three vertices: `share_card`,
`share_bio`, `share_context`.

  * DEVICE-PRESENT paths (card, in-person, normal auth) release `share_bio` via
    the Secure Enclave (robust biometric match, works on real fingers/faces).
    The Enclave-sealed copy is DEVICE-BOUND.
  * TOTAL-LOSS / catastrophic path (new device; the old device is gone) recovers
    from the two PORTABLE shares — `share_card` (JavaCard / Half B, which you carry)
    and `share_context` (the trusted-context / backend vertex, released only under
    the in-person recovery ceremony). It takes NO Enclave and NO biometric.

Fuzzy extractor RETIRED (2026-07-17, TRUST_LAYER.md #7): Atlas extracts no key from
raw biometrics and stores no biometric sketch. Biometric matching is the Secure
Enclave (device-present) or a LIVE recovery person (total loss — see
`realid.recovery_anchor`); at total loss the anti-spoof is that accountable human,
not a reconstructed key.

Why stratify: the Enclave is robust but device-bound, so it CANNOT be the total-loss
path (losing the device loses the sealed key). Total loss therefore rides the two
portable threshold shares, which by construction do not depend on the lost device.

Invariants preserved:
  * "Never store the biometric" — the Enclave keeps the template sealed and matches
    internally; nothing biometric is persisted outside it.
  * 2-of-3 threshold — unchanged.
  * Total-loss recovery NEVER depends on a single device's Enclave (takes no Enclave).

Precondition for every path (§7.3): attested HW+FW + (device-present) live biometric.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field

from ..crypto import shamir
from ..crypto.primitives import random_bytes
from .enclave import SecureEnclave
from .identity import IdentityTree, build_identity_tree

# Passcode KDF: salted + stretched. The recovery-child passcode is a low-entropy
# selector (the real secrecy is biometric + threshold), but it must still resist
# offline brute force if the enrolment record leaks — so never store a bare hash.
_PASSCODE_ITERS = 100_000


def _derive_passcode(passcode: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", passcode.encode(), salt, _PASSCODE_ITERS)


class RecoveryError(RuntimeError):
    pass


class AttestationRequired(RecoveryError):
    """Precondition (§7.3): every path requires attested HW+FW."""


class HolderAuthorityRequired(RecoveryError):
    """Holder-authority gate (Credential PQC Posture §6): recovery is triggered
    ONLY by the user's own authority (unlock / in-person ceremony). There is no
    operator, court, or system path — same discipline as `rerooting.py`'s
    OperatorForbidden. Modelled here as an explicit `user_authorized` flag that
    no operator code path can set; the real binding is the live biometric +
    threshold + in-person ceremony the paths already require."""


_BIO_LABEL = b"share-bio"


@dataclass
class RecoveryEnrolment:
    """Artifacts produced once, at enrolment (§7.2)."""

    share_card: shamir.Share          # portable; goes on the JavaCard
    share_context: shamir.Share       # portable; trusted-context / backend vertex
    # device-present release of share_bio (Secure Enclave, robust, device-bound):
    enclave_device_id: bytes
    enclave_sealed_bio: bytes
    recovery_child_handle: bytes
    _passcode_salt: bytes = field(repr=False, default=b"")
    _passcode_hash: bytes = field(repr=False, default=b"")
    # Lockout counter lives HERE (the persisted record), not on the gate object —
    # otherwise an attacker resets the limit by re-instantiating the gate.
    _child_attempts_remaining: int = 3


def enrol_recovery(
    tree: IdentityTree, biometric_template: bytes, *, device: SecureEnclave, passcode: str
) -> RecoveryEnrolment:
    """Split the TSK seed 2-of-3 and bind `share_bio` to the device Enclave
    (device-present). Total-loss recovery uses the two PORTABLE shares (card +
    context) and needs no biometric release of `share_bio`."""
    share_card, share_bio, share_context = shamir.split(tree.tsk_seed, n=3, k=2)

    # Device-present: enrol the biometric in the Enclave and seal share_bio to it.
    device.enrol_biometric(biometric_template)
    enclave_sealed_bio = device.seal(share_bio.encode(), label=_BIO_LABEL)

    return RecoveryEnrolment(
        share_card=share_card,
        share_context=share_context,
        enclave_device_id=device.device_id,
        enclave_sealed_bio=enclave_sealed_bio,
        recovery_child_handle=tree.child("recovery").handle,
        _passcode_salt=(salt := random_bytes(16)),
        _passcode_hash=_derive_passcode(passcode, salt),
    )


def _rebuild(seed: bytes) -> IdentityTree:
    return build_identity_tree(seed)


# ---------------------------------------------------------------------------
# DEVICE-PRESENT paths — Secure Enclave biometric release (robust, device-bound)
# ---------------------------------------------------------------------------

def _enclave_bio_share(enr: RecoveryEnrolment, device: SecureEnclave, live_sample: bytes):
    if device.device_id != enr.enclave_device_id:
        # device-bound: only the enrolled device's Enclave can release it
        return None
    raw = device.release(enr.enclave_sealed_bio, live_sample=live_sample, label=_BIO_LABEL)
    return shamir.Share.decode(raw) if raw is not None else None


def recover_via_card(
    enr: RecoveryEnrolment, *, device: SecureEnclave, card_share: shamir.Share,
    live_biometric: bytes, attested: bool, user_authorized: bool,
) -> IdentityTree:
    """Remote self-service on the ENROLLED device: card share + Enclave-released
    biometric share -> 2-of-3 (§7.3). Robust matching (works on real fingers)."""
    if not user_authorized:
        raise HolderAuthorityRequired("card path requires the user's own authority (no operator path)")
    if not attested:
        raise AttestationRequired("card path requires attested HW+FW")
    bio_share = _enclave_bio_share(enr, device, live_biometric)
    if bio_share is None:
        raise RecoveryError("Enclave biometric release failed (no match / wrong device)")
    return _rebuild(shamir.combine([card_share, bio_share]))


def recover_in_person(
    enr: RecoveryEnrolment, *, device: SecureEnclave, live_biometric: bytes,
    attested: bool, in_person_trusted_context: bool, user_authorized: bool,
) -> IdentityTree:
    """In-person forward-recovery on the ENROLLED device: Enclave-released
    biometric share + trusted-context vertex -> 2-of-3 (§7.3). The blind
    System-ID forward-recovers everything; the root stays blind."""
    if not user_authorized:
        raise HolderAuthorityRequired("in-person path requires the user's own authority (no operator path)")
    if not attested:
        raise AttestationRequired("in-person path requires attested HW+FW")
    if not in_person_trusted_context:
        raise RecoveryError("in-person trusted context not established")
    bio_share = _enclave_bio_share(enr, device, live_biometric)
    if bio_share is None:
        raise RecoveryError("Enclave biometric release failed (no match / wrong device)")
    return _rebuild(shamir.combine([bio_share, enr.share_context]))


def release_for_auth(enr: RecoveryEnrolment, *, device: SecureEnclave, live_biometric: bytes) -> bool:
    """Normal auth: the Enclave robustly releases on a live biometric match.
    Returns whether the device-present human-proof succeeded (no secret leaves)."""
    return _enclave_bio_share(enr, device, live_biometric) is not None


# ---------------------------------------------------------------------------
# TOTAL-LOSS / catastrophic path — the two PORTABLE threshold shares.
# Takes NO Enclave and NO biometric: by construction it cannot depend on the
# lost device, and the anti-spoof is the in-person recovery ceremony.
# ---------------------------------------------------------------------------

def recover_total_loss(
    enr: RecoveryEnrolment, *, card_share: shamir.Share, context_share: shamir.Share,
    attested: bool, in_person_trusted_context: bool, user_authorized: bool,
) -> IdentityTree:
    """Recovery from TOTAL DEVICE LOSS on a NEW device (§7.3, catastrophic).

    Combines the two PORTABLE threshold shares — `card_share` (Half B, which you
    carry) and `context_share` (the trusted-context / backend vertex, released only
    under the in-person recovery ceremony) — into 2-of-3. NEVER touches an Enclave
    and uses NO biometric: identity assurance at total loss is the live, accountable
    recovery person of the in-person ceremony (see `realid.recovery_anchor`), not a
    stored template or a reconstructed key.
    """
    if not user_authorized:
        raise HolderAuthorityRequired("total-loss recovery requires the user's own authority (no operator path)")
    if not attested:
        raise AttestationRequired("total-loss path requires attested HW+FW (new device)")
    if not in_person_trusted_context:
        raise RecoveryError("total-loss recovery is in-person only")
    return _rebuild(shamir.combine([card_share, context_share]))


# ---------------------------------------------------------------------------
# Recovery-child entry — private handle + 3-attempt passcode (selector/gate).
# ---------------------------------------------------------------------------

@dataclass
class RecoveryChildSession:
    handle: bytes
    attempts_remaining: int


class RecoveryChildGate:
    """Private handle + 3-attempt passcode (selector/gate, not the security; §7.3).

    The attempt counter is PERSISTED in the enrolment record (`enr`), not on this
    object — so re-instantiating the gate does NOT reset the lockout (that bypass
    would otherwise turn the 3-attempt limit into unlimited guesses). A correct
    passcode does not consume an attempt; only failures do.
    """

    def __init__(self, enr: RecoveryEnrolment):
        self._enr = enr

    @property
    def attempts_remaining(self) -> int:
        return self._enr._child_attempts_remaining

    def attempt(self, *, asserted_handle: bytes, passcode: str, attested: bool,
                user_authorized: bool = True) -> RecoveryChildSession:
        if not user_authorized:
            raise HolderAuthorityRequired("recovery-child path requires the user's own authority")
        if not attested:
            raise AttestationRequired("recovery-child path requires attested HW+FW")
        if self._enr._child_attempts_remaining <= 0:
            raise RecoveryError("passcode attempts exhausted; full recovery required")
        if asserted_handle != self._enr.recovery_child_handle:
            self._enr._child_attempts_remaining -= 1
            raise RecoveryError("unknown recovery-child handle")
        candidate = _derive_passcode(passcode, self._enr._passcode_salt)
        if not hmac.compare_digest(candidate, self._enr._passcode_hash):
            self._enr._child_attempts_remaining -= 1
            raise RecoveryError(f"bad passcode ({self._enr._child_attempts_remaining} attempts left)")
        return RecoveryChildSession(
            handle=self._enr.recovery_child_handle,
            attempts_remaining=self._enr._child_attempts_remaining,
        )
