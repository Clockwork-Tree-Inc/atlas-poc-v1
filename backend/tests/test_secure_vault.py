"""C9 — on-phone secure vault: presence-gated, provenance-stamped, backup choice.
Cryptographic unreadability (not physical exclusion of Apple)."""

import os

import pytest

from atlas.beacon import LocalBeacon
from atlas.crypto import kem
from atlas.keys.enclave import SecureEnclave
from atlas.keys.identity import build_identity_tree
from atlas.liveness.bayes import LivenessGate, PoLEState
from atlas.liveness.synthetic import live_stream
from atlas.session.secure_vault import BackupChoice, BackupNotEnabled, NotPresent, SecureVault

BIO = b"\xa5" * 64                       # enrolled biometric template (test)


def _live_pole(epoch=b"\x00" * 8):
    g = LivenessGate()
    for _, (psl, psnl) in live_stream(40):
        g.update(p_s_given_live=psl, p_s_given_not_live=psnl)
    return g.state(sensor_digest=b"s", drand_round=epoch)


def _dead_pole(epoch=b"\x00" * 8):
    return PoLEState(p_live=0.0, state_digest=b"d", drand_round=epoch, operate=False)


def _vault(backup=BackupChoice.PHONE_ONLY):
    tree = build_identity_tree(os.urandom(32))
    return SecureVault(enclave=SecureEnclave(), biometric=BIO,
                       author=tree.child("authorship"), backup=backup), tree


def test_put_get_roundtrip_under_presence():
    v, _ = _vault()
    b = LocalBeacon().round_at(1.0)
    v.put("note", b"my seed phrase", live_biometric=BIO, pole=_live_pole(b.drand_round()), beacon_round=b)
    assert v.get("note", live_biometric=BIO, pole=_live_pole(b.drand_round())) == b"my seed phrase"


def test_no_presence_fails_closed():
    v, _ = _vault()
    b = LocalBeacon().round_at(1.0)
    # PoLE not operating -> storage key not released
    with pytest.raises(NotPresent):
        v.put("x", b"data", live_biometric=BIO, pole=_dead_pole(), beacon_round=b)


def test_wrong_biometric_fails_closed():
    v, _ = _vault()
    b = LocalBeacon().round_at(1.0)
    v.put("x", b"data", live_biometric=BIO, pole=_live_pole(b.drand_round()), beacon_round=b)
    with pytest.raises(NotPresent):
        v.get("x", live_biometric=b"\x00" * 64, pole=_live_pole(b.drand_round()))   # not the enrolled finger


def test_at_rest_is_unreadable_brick():
    v, _ = _vault()
    b = LocalBeacon().round_at(1.0)
    v.put("x", b"PLAINTEXT-SECRET", live_biometric=BIO, pole=_live_pole(b.drand_round()), beacon_round=b)
    brick = v.raw_at_rest("x")
    assert b"PLAINTEXT-SECRET" not in brick and len(brick) > 16


def test_provenance_stamp_binds_author_and_detects_tampering():
    v, tree = _vault()
    b = LocalBeacon().round_at(1.0)
    v.put("doc", b"authored content", live_biometric=BIO, pole=_live_pole(b.drand_round()), beacon_round=b)
    item = v._store["doc"]
    assert item.stamp.author_handle == tree.child("authorship").handle
    assert item.stamp.verify(tree.child("authorship").public)
    # corrupt the stored ciphertext -> AEAD open fails on get
    v._store["doc"].ciphertext = v._store["doc"].ciphertext[:-1] + bytes([v._store["doc"].ciphertext[-1] ^ 0xFF])
    with pytest.raises(Exception):
        v.get("doc", live_biometric=BIO, pole=_live_pole(b.drand_round()))


def test_phone_only_refuses_export():
    v, _ = _vault(BackupChoice.PHONE_ONLY)
    b = LocalBeacon().round_at(1.0)
    with pytest.raises(BackupNotEnabled):
        v.export_backup(kem.generate_keypair().public, live_biometric=BIO, pole=_live_pole(b.drand_round()))


def test_noncustodial_backup_host_blind_recovery_restores():
    v, _ = _vault(BackupChoice.NONCUSTODIAL)
    b = LocalBeacon().round_at(1.0)
    v.put("k", b"backed-up-secret", live_biometric=BIO, pole=_live_pole(b.drand_round()), beacon_round=b)
    recovery = kem.generate_keypair()
    blob = v.export_backup(recovery.public, live_biometric=BIO, pole=_live_pole(b.drand_round()))
    # a storage host holding the blob sees no plaintext...
    assert b"backed-up-secret" not in repr({k: vv for k, vv in blob.items() if k != "items"}).encode()
    # ...and cannot restore without the recovery key
    with pytest.raises(Exception):
        SecureVault.restore_backup(blob, kem.generate_keypair(), "k", blob["items"]["k"]["ciphertext"])
    # the user's recovery key restores it
    assert SecureVault.restore_backup(blob, recovery, "k", blob["items"]["k"]["ciphertext"]) == b"backed-up-secret"
