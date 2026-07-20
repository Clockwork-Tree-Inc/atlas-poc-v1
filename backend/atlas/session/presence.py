"""Presence-conditioned epoch-key unwrap (Locked Model §2.3, FIX #7).

Ratcheting is STRUCTURALLY gated on live enrolled presence — not by a separable
"if present" check that could be skipped, but by making the epoch key itself
unusable without presence:

    enrolled-live-user + continuously-present
        -> Secure-Enclave releases the enrollment secret
        -> unwrap the current epoch key
        -> access the current LK
        -> ratchet.

The epoch key is delivered WRAPPED. Unwrapping requires the enrollment secret,
which the device's Secure Enclave releases ONLY on a live biometric match while
PoLE is operating. No presence -> no release -> the AEAD unwrap MATHEMATICALLY
fails -> no epoch key -> no LK -> no ratchet, by construction. There is no code
path to a session key that bypasses the unwrap.

Honest boundary: the enclave-gated release is modelled (SecureEnclave); on device
the same property is the real Secure Enclave releasing a key under biometry.
"""

from __future__ import annotations

from typing import Optional

from ..crypto.primitives import aead_decrypt, aead_encrypt, hkdf
from ..keys.enclave import SecureEnclave
from ..liveness.bayes import PoLEState

_ENROLL_LABEL = b"atlas/epoch-enroll"
_UNWRAP_AAD = b"atlas/epoch-key"


def _unwrap_key(enrollment_secret: bytes, drand_round: bytes) -> bytes:
    return hkdf(ikm=enrollment_secret, info=b"atlas/epoch-unwrap|" + drand_round, length=32)


def wrap_epoch_key(epoch_key: bytes, *, enrollment_secret: bytes, drand_round: bytes) -> bytes:
    """Server side: wrap the epoch key to the device's enrollment secret so only a
    present, enrolled device can unwrap it (demonstrates no-epoch-key -> no-unwrap)."""
    return aead_encrypt(_unwrap_key(enrollment_secret, drand_round), epoch_key, aad=_UNWRAP_AAD)


def unwrap_epoch_key(wrapped: bytes, *, presence_secret: bytes, drand_round: bytes) -> bytes:
    """Device side: unwrap using the enclave-RELEASED presence secret. Raises if
    the secret is wrong/absent (i.e. not the enrolled, present device)."""
    return aead_decrypt(_unwrap_key(presence_secret, drand_round), wrapped, aad=_UNWRAP_AAD)


# --- epoch key WRAPS the LK (§2.5 / FIX #15) --------------------------------
# The (network-public) epoch key is what unlocks the (private) LK. Dependency
# chain: continuity=yes -> unwrap epoch key -> unlock LK -> derive session key.
# The epoch key is safe to be public precisely because unwrapping it is
# continuity-gated: a non-present enrolled participant holds the public epoch key
# but cannot get past the presence gate, so it unlocks nothing.
_LK_AAD = b"atlas/lk"


def _lk_key(epoch_key: bytes, drand_round: bytes) -> bytes:
    return hkdf(ikm=epoch_key, info=b"atlas/lk-unlock|" + drand_round, length=32)


def wrap_lk(lk: bytes, *, epoch_key: bytes, drand_round: bytes) -> bytes:
    """Server side: wrap the private LK UNDER the (public) epoch key. Only a party
    holding the current epoch key can unlock the LK."""
    return aead_encrypt(_lk_key(epoch_key, drand_round), lk, aad=_LK_AAD)


def unlock_lk(wrapped_lk: bytes, *, epoch_key: bytes, drand_round: bytes) -> bytes:
    """Unlock the LK with the (unwrapped) epoch key. Raises if the epoch key is
    wrong — no epoch key -> no LK."""
    return aead_decrypt(_lk_key(epoch_key, drand_round), wrapped_lk, aad=_LK_AAD)


class EnrolledPresence:
    """The device-side enrollment binding: the enrollment secret sealed in the
    Secure Enclave, released ONLY on live enrolled presence."""

    def __init__(self, enrollment_secret: bytes, *, enclave: SecureEnclave, biometric: bytes):
        if not enclave.has_biometric:
            enclave.enrol_biometric(biometric)
        self._sealed = enclave.seal(enrollment_secret, label=_ENROLL_LABEL)
        self._enclave = enclave

    def release(self, *, live_biometric: bytes, pole: PoLEState) -> Optional[bytes]:
        """Release the enrollment secret iff the user is CONTINUOUSLY PRESENT:
        PoLE operating (continuity intact) AND a live biometric match inside the
        enclave. Returns None otherwise -> the caller cannot unwrap the epoch key."""
        if not pole.operate:                     # continuity broken -> no release
            return None
        return self._enclave.release(self._sealed, live_sample=live_biometric, label=_ENROLL_LABEL)
