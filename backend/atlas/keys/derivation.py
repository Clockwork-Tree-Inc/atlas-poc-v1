"""Session key derivation, forward-secret ratchet, contexts and tokens (§2.2, §2.3).

Locked Model §2.3 — the ONE principle: value = QRNG (clean); timing/liveness
times draws and gates operations but NEVER enters a value or KDF.

  SessKey = HKDF( PoLE_value, LK, epoch_key, prev_key, context_separator )

  * PoLE_value      — a physiologically-TIMED QRNG value: the enrolled ring's
                      live signal times WHEN the device QRNG fires; the fired
                      value is clean QRNG (raw physiology never enters it). This
                      replaces the earlier un-timed `local_qrng_draw`.
  * LK, epoch_key   — clean QRNG values; present ONLY because continuity gated
                      their unwrap (epoch key unwraps LK; see session/presence).
  * NO continuity_flag (continuity is upstream — it gates the unwrap, it is not a
    KDF ingredient), NO raw physiology, NO drand.

(The `coupled` variant below is a legacy alternative claim, not the default.)

Forward-secret ratchet (§2.2):
  K[t+1] = HKDF( K[t] || H(entropy_t) || beacon_t || drand_round )

SessKey is RAM-only and must be destroyed on liveness break / logout /
attestation failure / epoch boundary (§2.2). `SessionKey.destroy()` zeroises it;
the containment tests assert a destroyed key cannot decrypt.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..crypto.primitives import H, hkdf_combine
from ..params import (
    CONTEXT_RECOGNITION,
    CONTEXT_STORAGE,
    CONTEXT_TUNNEL,
    LABEL_RATCHET,
    LABEL_SESSION,
)

_CONTEXTS = {
    "storage": CONTEXT_STORAGE,
    "recognition": CONTEXT_RECOGNITION,
    "tunnel": CONTEXT_TUNNEL,
}


class KeyDestroyedError(RuntimeError):
    """Raised when a destroyed (RAM-wiped) session key is used."""


@dataclass
class SessionKey:
    """RAM-only session key material (§2.2). Never written to storage."""

    drand_round: bytes
    _key: bytearray = field(repr=False)
    _alive: bool = True

    @property
    def key(self) -> bytes:
        if not self._alive:
            raise KeyDestroyedError("session key was destroyed (liveness/epoch)")
        return bytes(self._key)

    def context_key(self, context: str) -> bytes:
        """Derive a purpose-scoped key (§2.3 HKDF info label per purpose)."""
        if context not in _CONTEXTS:
            raise ValueError(f"unknown context {context!r}")
        return hkdf_combine([self.key], info=_CONTEXTS[context], length=32)

    def destroy(self) -> None:
        """Zeroise the key (the primary containment mechanism, §2.2)."""
        for i in range(len(self._key)):
            self._key[i] = 0
        self._alive = False

    @property
    def alive(self) -> bool:
        return self._alive


def derive_session_key_decoupled(
    *,
    lk: bytes,
    epoch_key: bytes,
    pole_value: bytes,
    prev_key: bytes,
    context_separator: bytes,
    drand_round: bytes,
) -> SessionKey:
    """Session key = HKDF(PoLE_value, LK, epoch_key, prev_key, ctx) (§2.3).

    `pole_value` is the physiologically-TIMED QRNG value (clean QRNG whose firing
    was timed by the ring's live signal). Continuity is NOT an input here — it is
    upstream, gating whether LK/epoch_key could be unwrapped at all. No raw
    physiology, no drand. (Input list order is preserved for cross-impl parity.)"""
    material = hkdf_combine(
        [lk, epoch_key, pole_value, prev_key, context_separator],
        info=LABEL_SESSION,
        length=32,
    )
    return SessionKey(drand_round=drand_round, _key=bytearray(material))


def derive_session_key_coupled(
    *, tsk: bytes, dev_key: bytes, pole_state: bytes, beacon: bytes, drand_round: bytes
) -> SessionKey:
    """REFERENCE ONLY — NOT a live code path. Do NOT wire into session derivation.

    The Math Spec §A "coupled" embodiment folds the PoLE *state* into the KDF. We
    DELIBERATELY DO NOT use it: mixing low-entropy, estimable, non-reproducible
    liveness/timing data into key material can only weaken the key (shrinks the
    keyspace, and a measurement of your biology would then help derive the key). The
    presence BINDING it aims for is already provided — cleanly — by GATING the unwrap
    of LK/epoch_key upstream (see `derive_session_key_decoupled` + session/presence).

    DECISION (stands): value = QRNG (clean); timing/liveness TIMES the QRNG firing and
    GATES operations, but NEVER enters a value/KDF. This function exists only so its
    behavior is pinned (test_coupled_epoch_gaps.py); the live path is the decoupled one.
    """
    material = hkdf_combine(
        [tsk, dev_key, pole_state, beacon], info=LABEL_SESSION, length=32
    )
    return SessionKey(drand_round=drand_round, _key=bytearray(material))


def ratchet(prev_key: bytes, *, entropy_t: bytes, beacon_t: bytes, drand_round: bytes) -> bytes:
    """Forward-secret ratchet step (§2.2).

    K[t+1] = HKDF( K[t] || H(entropy_t) || beacon_t || drand_round ).
    One-way: K[t] cannot be recovered from K[t+1] (a captured later key cannot
    read earlier messages, and vice-versa).
    """
    return hkdf_combine(
        [prev_key, H(entropy_t), beacon_t, drand_round], info=LABEL_RATCHET, length=32
    )
