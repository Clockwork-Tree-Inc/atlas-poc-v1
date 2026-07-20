"""USB DualDrive recovery share: a lost drive is opaque, one share can't
reconstruct, but the USB share + another vertex recovers the TSK."""

import os

import pytest

from atlas.crypto import kem, shamir
from atlas.keys.enclave import SecureEnclave
from atlas.keys.identity import build_identity_tree
from atlas.keys.recovery import enrol_recovery
from atlas.keys.usb_recovery import (
    USBRecoveryBlob,
    USBRecoveryError,
    read_share_from_usb,
    write_share_to_usb,
)

BIO = b"\xa5" * 128        # enrolled biometric template for the Enclave in enrol_recovery


def test_write_read_roundtrip_through_drive_bytes():
    share = shamir.split(b"S" * 32, n=3, k=2)[0]
    recovery = kem.generate_keypair()
    blob = write_share_to_usb(share, recovery.public)
    # survives serialization to/from the raw bytes written on the drive
    on_disk = USBRecoveryBlob.from_bytes(blob.to_bytes())
    assert read_share_from_usb(on_disk, recovery).encode() == share.encode()


def test_lost_drive_is_opaque_without_the_recovery_key():
    share = shamir.split(b"S" * 32, n=3, k=2)[0]
    recovery = kem.generate_keypair()
    blob = write_share_to_usb(share, recovery.public)
    # a finder sees no plaintext share...
    assert share.encode() not in blob.to_bytes()
    # ...and cannot read it with a different key (fail-closed)
    with pytest.raises(USBRecoveryError):
        read_share_from_usb(blob, kem.generate_keypair())


def test_usb_share_plus_one_vertex_recovers_but_one_share_alone_cannot():
    tree = build_identity_tree(os.urandom(32))
    enr = enrol_recovery(tree, BIO, device=SecureEnclave(), passcode="pw")
    recovery = kem.generate_keypair()

    # the USB carries the 'card' vertex, encrypted
    blob = write_share_to_usb(enr.share_card, recovery.public)
    usb_share = read_share_from_usb(blob, recovery)

    # USB share + the trusted-context vertex -> the TSK seed (2-of-3)
    assert shamir.combine([usb_share, enr.share_context]) == tree.tsk_seed
    # the USB share ALONE cannot reconstruct (needs k-of-n) — combine refuses
    with pytest.raises(ValueError):
        shamir.combine([usb_share])
