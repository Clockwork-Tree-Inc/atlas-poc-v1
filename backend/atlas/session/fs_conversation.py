"""Forward-secret two-party conversation over the blind relay (§2.2, §10.1).

Each message is sealed under a per-message key drawn from a delete-as-you-go
chain, seeded from the live co-derived session/LK material both parties share. The
chain advances ONE-WAY (HKDF), so a leaked message/chain key reveals neither past
nor future message keys. It is deterministic, so both sides ratchet in lockstep
with NO per-message secret transmitted. Separate chains per direction (A->B,
B->A), Signal-style. The blind node only ever relays ciphertext.

This is the forward-secret wiring the relay client lacked: content is sealed under
the RATCHETED key, seeded from the STATIC KEM channel key AND the live co-derived
LK ("static keys for who-you-are, session keys for what-you-say") — never a static
key alone. Byte-parity target for the Swift port (Device.messageRatchetStep is the
primitive; this composes it per party).
"""

from __future__ import annotations

from typing import List, Tuple

from ..crypto.primitives import aead_decrypt, aead_encrypt, hkdf_combine

_CHAIN_INFO = b"atlas/fs-conv/chain"


def seed_chain(*, channel_key: bytes, lk: bytes, drand_round: bytes, direction: bytes) -> bytes:
    """Both parties derive the SAME seed for a given direction from shared live
    material: the static KEM channel key + the live co-derived LK + the epoch.
    `direction` (e.g. b"A->B") makes the two directions independent chains."""
    return hkdf_combine([channel_key, lk, drand_round, direction], info=_CHAIN_INFO, length=32)


def _step(chain_key: bytes, *, beacon_t: bytes, drand_round: bytes) -> Tuple[bytes, bytes]:
    """One-way step -> (message_key, next_chain_key). The caller uses message_key
    once and discards the old chain_key; neither can be recovered from what follows."""
    mk = hkdf_combine([chain_key, b"mk", beacon_t, drand_round], info=_CHAIN_INFO, length=32)
    ck = hkdf_combine([chain_key, b"ck", beacon_t, drand_round], info=_CHAIN_INFO, length=32)
    return mk, ck


class FSChain:
    """One direction of the conversation. `seal`/`open` advance the same one-way
    chain in lockstep; each message key is used exactly once, then gone."""

    def __init__(self, seed: bytes, *, drand_round: bytes):
        self._ck = seed
        self._drand_round = drand_round

    def seal(self, plaintext: bytes, *, beacon_t: bytes, aad: bytes = b"") -> bytes:
        mk, nxt = _step(self._ck, beacon_t=beacon_t, drand_round=self._drand_round)
        self._ck = nxt                                   # advance; old chain key discarded
        return aead_encrypt(mk, plaintext, aad=aad)      # message key used once

    def open(self, blob: bytes, *, beacon_t: bytes, aad: bytes = b"") -> bytes:
        mk, nxt = _step(self._ck, beacon_t=beacon_t, drand_round=self._drand_round)
        self._ck = nxt
        return aead_decrypt(mk, blob, aad=aad)


def derive_chain(seed: bytes, *, count: int, beacon_t: bytes, drand_round: bytes) -> List[Tuple[bytes, bytes]]:
    """Reproduce the first `count` (message_key, chain_key_BEFORE_this_step) pairs
    from a seed. Test/audit helper: lets a caller show that the chain key leaked at
    step i cannot derive the message key of any step < i (one-way forward secrecy)."""
    out: List[Tuple[bytes, bytes]] = []
    ck = seed
    for _ in range(count):
        mk, nxt = _step(ck, beacon_t=beacon_t, drand_round=drand_round)
        out.append((mk, ck))
        ck = nxt
    return out
