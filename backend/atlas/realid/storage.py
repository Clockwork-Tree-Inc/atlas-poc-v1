"""Non-custodial storage of the (test) real-ID material (Real-ID spec §4).

Atlas is not a honeypot by construction. Two modes:
  * On-device — the real-ID material lives in device secure storage (Secure
    Enclave-protected), never leaving it; the backend holds only the
    verification STATUS attestation, never the ID.
  * Split-and-distributed — Shamir-split (reuse the existing 2-of-3) across
    device + user-held + an encrypted cloud share, so no single store holds the
    ID; reconstruct only on-device, on consent, for an L2 surface.

Assertion (tested): no single non-device location can reconstruct the ID.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional

from ..crypto import shamir
from ..crypto.primitives import aead_decrypt, aead_encrypt, hkdf


class NonCustodyError(Exception):
    pass


class OnDeviceStore:
    """The (test) ID encrypted under a key derived from the real-ID CHILD secret;
    never leaves the device. The backend gets only status (handled elsewhere)."""

    def __init__(self, realid_child_secret: bytes):
        self._key = hkdf(ikm=realid_child_secret, info=b"atlas/realid/ondevice", length=32)
        self._blob: Optional[bytes] = None

    def store(self, test_id_material: bytes) -> None:
        self._blob = aead_encrypt(self._key, test_id_material, aad=b"atlas/realid")

    def surface(self) -> bytes:
        if self._blob is None:
            raise NonCustodyError("no real-ID stored")
        return aead_decrypt(self._key, self._blob, aad=b"atlas/realid")


@dataclass
class SplitStore:
    """Shamir 2-of-3 across device + user-held + cloud. Reconstruct on-device.
    The `cloud`/server share is the only thing a non-device location holds — one
    share, insufficient alone."""

    device_share: shamir.Share
    user_share: shamir.Share
    cloud_share: shamir.Share

    @staticmethod
    def split(test_id_material: bytes) -> "SplitStore":
        d, u, c = shamir.split(test_id_material, n=3, k=2)
        return SplitStore(device_share=d, user_share=u, cloud_share=c)

    def reconstruct_on_device(self, *, user_share: shamir.Share) -> bytes:
        """On-device reconstruction uses the device share + the user-held share
        (2-of-3). The cloud/server share is never required and never sufficient
        alone."""
        return shamir.combine([self.device_share, user_share])

    def server_holds(self) -> shamir.Share:
        """What a non-device server location holds: exactly ONE share."""
        return self.cloud_share


def assert_non_custody(server_artifacts: Dict[str, object]) -> None:
    """Assert the server/backend holds only status + at most one share, never a
    reconstructable ID (Real-ID spec §4 'assert non-custody')."""
    shares = [v for v in server_artifacts.values() if isinstance(v, shamir.Share)]
    if len(shares) >= 2:
        raise NonCustodyError("server holds >= 2 shares — ID is reconstructable (custodial!)")
    for v in server_artifacts.values():
        if isinstance(v, (bytes, bytearray)) and len(v) > 0 and not isinstance(v, shamir.Share):
            # a raw plaintext ID-looking blob in server storage is a violation
            raise NonCustodyError("server holds raw ID-like material (custodial!)")
