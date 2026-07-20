"""Symmetric primitives, hashes and KDF (§1.3, §4.1).

Canonical roles from §1.3:
  * Symmetric  -> AES-256-GCM
  * KDF        -> HKDF over SHA-2 (SHA-256) / SHA-3
The spec also names BLAKE3; SHA-256/SHA-3 from `cryptography` cover the PoC and
keep the dependency surface small.
"""

from __future__ import annotations

import hashlib
import os
from typing import Iterable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

AES_KEY_BYTES = 32  # AES-256
GCM_NONCE_BYTES = 12


def random_bytes(n: int) -> bytes:
    """OS CSPRNG draw. §1.1: 'OS CSPRNG already adequate.'"""
    return os.urandom(n)


def sha256(*chunks: bytes) -> bytes:
    h = hashlib.sha256()
    for c in chunks:
        h.update(c)
    return h.digest()


def sha3_256(*chunks: bytes) -> bytes:
    h = hashlib.sha3_256()
    for c in chunks:
        h.update(c)
    return h.digest()


def H(*chunks: bytes) -> bytes:
    """The protocol hash H(...) used throughout the spec (PoLE_state, handles).

    SHA3-256 is used so H is distinct from the HKDF underlying hash and matches
    the spec's 'HKDF over SHA-3' note for state digests.
    """
    return sha3_256(*chunks)


def hkdf(
    *,
    ikm: bytes,
    info: bytes,
    salt: bytes | None = None,
    length: int = AES_KEY_BYTES,
) -> bytes:
    """HKDF<SHA-256> (§1.3 'CryptoKit HKDF<SHA256>')."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


def hkdf_combine(parts: Iterable[bytes], *, info: bytes, length: int = AES_KEY_BYTES) -> bytes:
    """Derive a key from an ordered list of inputs.

    The spec's derivations are written as HKDF(a, b, c, ...). We realise the
    multi-input form by length-prefix-concatenating the parts into the HKDF IKM
    so the boundaries are unambiguous (a||b cannot collide with a'||b').
    """
    buf = bytearray()
    for p in parts:
        if p is None:
            p = b""
        buf += len(p).to_bytes(4, "big")
        buf += p
    return hkdf(ikm=bytes(buf), info=info, length=length)


# ---------------------------------------------------------------------------
# AES-256-GCM (§4.1 vault and tunnel payloads)
# ---------------------------------------------------------------------------


def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """AES-256-GCM. Returns nonce || ciphertext||tag."""
    if len(key) != AES_KEY_BYTES:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    nonce = os.urandom(GCM_NONCE_BYTES)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + ct


def aead_decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    if len(key) != AES_KEY_BYTES:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    nonce, ct = blob[:GCM_NONCE_BYTES], blob[GCM_NONCE_BYTES:]
    return AESGCM(key).decrypt(nonce, ct, aad)
