"""Secure Enclave biometric-bound key release (model) — §0.3, §7.

Models Apple's Secure Enclave biometric release for the *device-present*
recovery paths and normal auth:

  * Enclave release: a robust biometric match UNLOCKS a secret SEALED inside a
    specific device's hardware. Robust on real fingers/faces, but DEVICE-BOUND —
    the sealed secret does not survive device loss (so it cannot be the total-loss
    path; total loss rides the portable threshold shares + the in-person ceremony).

This is the ONLY place biometric material is matched: Atlas extracts no key from
raw biometrics (the fuzzy extractor is retired — TRUST_LAYER.md #7). It preserves
the invariant "never store the biometric": the Enclave keeps the enrolled template
sealed under a non-extractable hardware key and matches inside its boundary; it is
never exposed. This Python model makes that boundary explicit so the stratified
recovery model (recovery.py) is testable off-device.

On iOS this is a real Secure Enclave key gated by `biometryCurrentSet` /
`LAContext`; see ios/AtlasApp/Enclave/SecureEnclaveStore.swift.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..crypto.primitives import aead_decrypt, aead_encrypt, random_bytes

# Apple's matcher tolerates real-world variation. We model "robust" as accepting
# samples within this fraction of differing bits from the enrolled template.
ROBUST_MATCH_MAX_BIT_DIFF = 0.35


def _bit_diff_ratio(a: bytes, b: bytes) -> float:
    if len(a) != len(b) or not a:
        return 1.0
    diff = sum(bin(x ^ y).count("1") for x, y in zip(a, b))
    return diff / (len(a) * 8)


class SecureEnclave:
    """Models ONE physical device's Secure Enclave.

    Holds a non-extractable hardware master key and (after enrolment) a sealed
    biometric template. Neither is ever returned. Secrets sealed here are
    device-bound: another device's Enclave cannot release them.
    """

    def __init__(self, device_id: bytes | None = None):
        self.device_id = device_id or random_bytes(16)
        self._master = random_bytes(32)          # non-extractable hardware key
        self._sealed_template: bytes | None = None

    # -- enrolment ----------------------------------------------------------

    def enrol_biometric(self, template: bytes) -> None:
        """Store the enrolled template SEALED under the hardware key. The
        template is never exposed outside the Enclave (matching is internal)."""
        self._sealed_template = aead_encrypt(self._master, template, aad=b"atlas/se/tmpl")

    @property
    def has_biometric(self) -> bool:
        return self._sealed_template is not None

    # -- matching (inside the boundary) -------------------------------------

    def _match(self, sample: bytes) -> bool:
        if self._sealed_template is None:
            return False
        template = aead_decrypt(self._master, self._sealed_template, aad=b"atlas/se/tmpl")
        return _bit_diff_ratio(template, sample) <= ROBUST_MATCH_MAX_BIT_DIFF

    # -- biometric-bound seal / release -------------------------------------

    def seal(self, secret: bytes, *, label: bytes = b"") -> bytes:
        """Seal a secret to THIS device, releasable only on a biometric match."""
        aad = b"atlas/se/seal|" + self.device_id + b"|" + label
        return aead_encrypt(self._master, secret, aad=aad)

    def release(self, sealed: bytes, *, live_sample: bytes, label: bytes = b"") -> bytes | None:
        """Release a sealed secret iff the live biometric matches (robustly) on
        THIS device. Returns None on mismatch or if the blob was sealed elsewhere
        (device-bound: another Enclave's master key won't decrypt it)."""
        if not self._match(live_sample):
            return None
        aad = b"atlas/se/seal|" + self.device_id + b"|" + label
        try:
            return aead_decrypt(self._master, sealed, aad=aad)
        except Exception:
            return None


@dataclass(frozen=True)
class EnclaveSealedShare:
    """A recovery share sealed for device-present release. Device-bound: it is
    stored on (and only usable by) the enrolled device's Enclave."""

    device_id: bytes
    sealed: bytes
