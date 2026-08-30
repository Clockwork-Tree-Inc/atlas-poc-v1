"""Encrypted vault at rest + the PQC layering rule (§4.1).

§4.1:
  * Vault (at rest) and tunnel payloads: AES-256-GCM under the storage-/tunnel-
    context key. The vault is encrypted at rest continuously.
  * PQC is spent only at public-key moments (wrapping a key for backup,
    encrypting a key to a recipient) via ML-KEM+X25519. Do NOT double-encrypt
    data bytes with PQC over AES-256. A purely local vault invokes no public-key
    step.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict

from ..crypto import kem
from ..crypto.primitives import aead_decrypt, aead_encrypt


class Vault:
    """A continuously-encrypted-at-rest key/value store.

    The storage key is derived from the session key's storage context (§2.3).
    Entries are only ever held as ciphertext; `get` decrypts on demand to RAM.
    """

    def __init__(self, storage_key: bytes):
        if len(storage_key) != 32:
            raise ValueError("storage key must be 32 bytes")
        self._storage_key = storage_key
        self._store: Dict[str, bytes] = {}

    def put(self, name: str, plaintext: bytes) -> None:
        self._store[name] = aead_encrypt(
            self._storage_key, plaintext, aad=name.encode()
        )

    def get(self, name: str) -> bytes:
        return aead_decrypt(self._storage_key, self._store[name], aad=name.encode())

    def raw_at_rest(self, name: str) -> bytes:
        """The ciphertext as stored — what an attacker with disk access sees.

        After a suspicious wipe the storage key is gone but this stays an
        unreadable brick (§5.4 'vault stays encrypted at rest')."""
        return self._store[name]

    def __contains__(self, name: str) -> bool:
        return name in self._store

    # -- PQC is spent only here: wrap a key to a recipient (§4.1) ------------

    @staticmethod
    def wrap_key_for_recipient(recipient: kem.HybridKEMPublic, key: bytes) -> dict:
        """Public-key moment: encrypt a symmetric key to a recipient (ML-KEM+X25519)."""
        enc = kem.encapsulate(recipient)
        wrapped = aead_encrypt(enc.shared, key, aad=b"atlas/key-wrap")
        return {
            "mlkem_ct": enc.mlkem_ct,
            "x25519_eph_pk": enc.x25519_eph_pk,
            "wrapped": wrapped,
        }

    @staticmethod
    def unwrap_key(recipient_kp: kem.HybridKEMKeypair, bundle: dict) -> bytes:
        shared = kem.decapsulate(
            recipient_kp, bundle["mlkem_ct"], bundle["x25519_eph_pk"]
        )
        return aead_decrypt(shared, bundle["wrapped"], aad=b"atlas/key-wrap")
