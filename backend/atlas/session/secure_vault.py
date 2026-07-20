"""On-phone secure vault — the user's "USB-like" sealed space (C9).

Drop anything in; it is sealed to a storage key that (a) lives sealed in the
non-exportable Secure Enclave, (b) is released ONLY on live presence (biometric
match + PoLE operating), and (c) each item carries a provenance stamp binding it
to the author + content + time.

BACKUP is a CHOICE the user makes per vault:
  * PHONE_ONLY   — safest; the storage key never leaves the device's Enclave.
    Lose the phone → lose the content (no off-device copy exists).
  * NONCUSTODIAL — recoverable; the storage key is KEM-wrapped (ML-KEM + X25519)
    to the user's RECOVERY public key and shipped as an opaque blob. The storage
    host cannot read it; only the user (via the recovery structure) can restore.

HONEST BOUNDARY (state it exactly): this is CRYPTOGRAPHIC UNREADABILITY — content
is encrypted to a key even Apple cannot extract (Secure-Enclave-sealed) and
presence-gated. It is NOT physical exclusion of Apple from the device. Claim
"even Apple can't read it," NOT "Apple can't reach the storage." The Enclave seal
here is modelled (`SecureEnclave`); on device it is the real SE.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional

from ..beacon.base import BeaconRound
from ..crypto import kem
from ..crypto.primitives import H, aead_decrypt, aead_encrypt, random_bytes
from ..crypto.sign import HybridSigPublic, sign, verify
from ..keys.enclave import SecureEnclave
from ..keys.identity import Child
from ..liveness.bayes import PoLEState

_VAULT_LABEL = b"atlas/secure-vault/storage-key"
_ITEM_AAD = b"atlas/secure-vault/item"
_BACKUP_LABEL = b"atlas/secure-vault/backup"


class BackupChoice(Enum):
    PHONE_ONLY = "phone_only"
    NONCUSTODIAL = "noncustodial"


class NotPresent(Exception):
    """The storage key was not released — no live presence (biometric + PoLE)."""


class BackupNotEnabled(Exception):
    """Export requested on a PHONE_ONLY vault."""


@dataclass(frozen=True)
class VaultStamp:
    """Provenance stamp bound to (author, content, epoch), signed by the author's
    pseudonym. Detects tampering and attributes the item."""

    author_handle: bytes
    content_hash: bytes
    drand_round: bytes
    signature: bytes

    def core(self) -> bytes:
        return H(b"atlas/vault-stamp", self.author_handle, self.content_hash, self.drand_round)

    def verify(self, author_public: HybridSigPublic) -> bool:
        return verify(author_public, self.core(), self.signature)


@dataclass
class VaultItem:
    ciphertext: bytes            # AES-256-GCM(storage_key, data) — nonce||ct
    stamp: VaultStamp


class SecureVault:
    """A presence-gated, provenance-stamping sealed store. The storage key is
    sealed in the Enclave and released per operation on live presence; it is not
    retained in the clear."""

    def __init__(self, *, enclave: SecureEnclave, biometric: bytes, author: Child,
                 backup: BackupChoice = BackupChoice.PHONE_ONLY):
        if not enclave.has_biometric:
            enclave.enrol_biometric(biometric)
        self._enclave = enclave
        self._author = author
        self._backup = backup
        # Generate the storage key, seal it in the Enclave, and DROP the plaintext.
        storage_key = random_bytes(32)
        self._sealed_storage = enclave.seal(storage_key, label=_VAULT_LABEL)
        self._store: Dict[str, VaultItem] = {}
        del storage_key                          # never retained in the clear

    @property
    def backup_choice(self) -> BackupChoice:
        return self._backup

    def _release(self, live_biometric: bytes, pole: PoLEState) -> bytes:
        """Release the storage key iff live+present. Presence = PoLE operating AND
        an Enclave biometric match. Otherwise raise (fail-closed)."""
        if not pole.operate:
            raise NotPresent("PoLE not operating (continuity broken)")
        key = self._enclave.release(self._sealed_storage, live_sample=live_biometric, label=_VAULT_LABEL)
        if key is None:
            raise NotPresent("biometric did not match on this device")
        return key

    # -- put / get (presence-gated) -----------------------------------------

    def put(self, name: str, data: bytes, *, live_biometric: bytes, pole: PoLEState,
            beacon_round: BeaconRound) -> None:
        key = self._release(live_biometric, pole)
        content_hash = H(b"atlas/vault-content", data)
        stamp_core = H(b"atlas/vault-stamp", self._author.handle, content_hash, beacon_round.drand_round())
        stamp = VaultStamp(author_handle=self._author.handle, content_hash=content_hash,
                           drand_round=beacon_round.drand_round(), signature=sign(self._author.keypair, stamp_core))
        self._store[name] = VaultItem(ciphertext=aead_encrypt(key, data, aad=_ITEM_AAD + name.encode()),
                                      stamp=stamp)

    def get(self, name: str, *, live_biometric: bytes, pole: PoLEState) -> bytes:
        key = self._release(live_biometric, pole)
        item = self._store[name]
        data = aead_decrypt(key, item.ciphertext, aad=_ITEM_AAD + name.encode())
        # provenance check: the stamp must bind THIS content to its author.
        if item.stamp.content_hash != H(b"atlas/vault-content", data) or \
                not item.stamp.verify(self._author.public):
            raise ValueError("provenance stamp mismatch (tampered item)")
        return data

    def raw_at_rest(self, name: str) -> bytes:
        """The ciphertext as stored — an unreadable brick without the sealed key."""
        return self._store[name].ciphertext

    def __contains__(self, name: str) -> bool:
        return name in self._store

    # -- backup CHOICE ------------------------------------------------------

    def export_backup(self, recovery_pub: kem.HybridKEMPublic, *, live_biometric: bytes,
                      pole: PoLEState) -> dict:
        """NONCUSTODIAL only: KEM-wrap the storage key to the user's recovery key
        and hand back {wrapped_key, items}. The host cannot read it — only the
        recovery key restores. PHONE_ONLY vaults refuse (no off-device copy)."""
        if self._backup != BackupChoice.NONCUSTODIAL:
            raise BackupNotEnabled("this vault is PHONE_ONLY; no off-device copy exists")
        key = self._release(live_biometric, pole)
        wrapped = kem.encapsulate(recovery_pub)
        # ship the storage key wrapped to recovery; items travel as their at-rest ct
        sealed_key = aead_encrypt(wrapped.shared, key, aad=_BACKUP_LABEL)
        return {
            "mlkem_ct": wrapped.mlkem_ct, "x25519_eph_pk": wrapped.x25519_eph_pk,
            "sealed_key": sealed_key,
            "items": {name: {"ciphertext": it.ciphertext, "stamp": it.stamp}
                      for name, it in self._store.items()},
        }

    @staticmethod
    def restore_backup(blob: dict, recovery_kp: kem.HybridKEMKeypair,
                       name: str, item_ct: bytes) -> bytes:
        """USER side: unwrap the storage key with the recovery keypair and decrypt
        one item. (The host that held `blob` never could.)"""
        shared = kem.decapsulate(recovery_kp, blob["mlkem_ct"], blob["x25519_eph_pk"])
        storage_key = aead_decrypt(shared, blob["sealed_key"], aad=_BACKUP_LABEL)
        return aead_decrypt(storage_key, item_ct, aad=_ITEM_AAD + name.encode())
