"""USB DualDrive — the recovery hardware factor (replaces the JavaCard for the
prototype: "USB flash drive instead of cards for now").

It carries ONE recovery vertex — the `share_card` Shamir share from
`recovery.enrol_recovery` — ENCRYPTED to the user's recovery key. Two guarantees:

  * A LOST DRIVE IS OPAQUE — the share is KEM-wrapped (ML-KEM-768 + X25519) to the
    recovery public key; whoever finds the drive sees only ciphertext and cannot
    read the share without the recovery private key.
  * ONE SHARE IS NOT ENOUGH — recovery is 2-of-3 Shamir, so the USB share alone
    cannot reconstruct the TSK; it must be combined with another vertex (Enclave
    bio / trusted context / in-person).

ROLE SEPARATION (see NAMING.md): like the YubiKey, the USB is a deliberate SECRET-
HOLDER (unlike the ring). Its job is recovery of CONTROL, restorable via the
identity system even if the drive itself is lost.

The physical file I/O on the Lexar D40e (USB-C into the iPhone 17) is device work;
this is the crypto reference the on-device writer/reader mirrors.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass

from ..crypto import kem, shamir
from ..crypto.primitives import aead_decrypt, aead_encrypt

_USB_AAD = b"atlas/usb-recovery/share"


class USBRecoveryError(Exception):
    """The USB blob could not be read with the given recovery key (wrong key /
    tampered / not a recovery blob)."""


@dataclass
class USBRecoveryBlob:
    """The opaque bytes written to the drive. Contains no plaintext share."""

    mlkem_ct: bytes
    x25519_eph_pk: bytes
    sealed_share: bytes

    def to_bytes(self) -> bytes:
        return json.dumps({
            "mlkem_ct": base64.b64encode(self.mlkem_ct).decode(),
            "x25519_eph_pk": base64.b64encode(self.x25519_eph_pk).decode(),
            "sealed_share": base64.b64encode(self.sealed_share).decode(),
        }).encode()

    @staticmethod
    def from_bytes(blob: bytes) -> "USBRecoveryBlob":
        o = json.loads(blob)
        return USBRecoveryBlob(
            mlkem_ct=base64.b64decode(o["mlkem_ct"]),
            x25519_eph_pk=base64.b64decode(o["x25519_eph_pk"]),
            sealed_share=base64.b64decode(o["sealed_share"]),
        )


def write_share_to_usb(share: shamir.Share, recovery_pub: kem.HybridKEMPublic) -> USBRecoveryBlob:
    """Encrypt a recovery Shamir share to the user's recovery key for the drive. The
    resulting blob is opaque to anyone who finds the drive."""
    enc = kem.encapsulate(recovery_pub)
    sealed = aead_encrypt(enc.shared, share.encode(), aad=_USB_AAD)
    return USBRecoveryBlob(mlkem_ct=enc.mlkem_ct, x25519_eph_pk=enc.x25519_eph_pk,
                           sealed_share=sealed)


def read_share_from_usb(blob: USBRecoveryBlob, recovery_kp: kem.HybridKEMKeypair) -> shamir.Share:
    """USER side: unwrap the share with the recovery keypair. Raises if the key is
    wrong / the blob is tampered (fail-closed)."""
    try:
        shared = kem.decapsulate(recovery_kp, blob.mlkem_ct, blob.x25519_eph_pk)
        return shamir.Share.decode(aead_decrypt(shared, blob.sealed_share, aad=_USB_AAD))
    except Exception as e:  # noqa: BLE001
        raise USBRecoveryError("could not read USB recovery share with this key") from e
