"""Local duress slice — panic-code decoy + zeroize-on-suspicion (Code Spec
Priority 3; Real-ID §7 / threat T-7, local device arm).

TWO composable mechanisms, both built on the existing fail-closed machinery
(`Vault` at-rest AES, `SecureEnclave`-style sealing):

  1. PANIC CODE -> DECOY, real secrets stay sealed.
     Two passcodes are enrolled. The NORMAL code unwraps the real storage key
     and opens the real vault. The PANIC code unwraps only a DECOY storage key
     and opens a plausible decoy vault. The two paths are surface-identical (both
     return a working vault view); only the internal `duress` flag and WHICH key
     materialises differ. The real storage key is NEVER derivable from the panic
     code — the panic path unwraps a different sealed blob under a different
     KDF key, so entering it under coercion reveals nothing real.

  2. ZEROIZE-ON-SUSPICION.
     On a coercion/tamper suspicion signal (a panic-wipe code, repeated auth
     failure, or a subsystem tamper flag), the real key material is destroyed:
     the sealed real key is dropped and any cached key scrubbed. Afterwards the
     real vault entries remain on disk as UNREADABLE BRICKS (no key -> AEAD
     fails), fail-closed by construction — there is no code path back to the
     plaintext once zeroized.

HONEST BOUNDARY (stubbed-and-specified, NOT built here):
  * Production sealing is the real Secure Enclave (`biometryCurrentSet`-gated
    non-extractable key), not this Python AEAD model.
  * Hardware anti-tamper zeroize (active mesh, epoxy, power-glitch detection) is
    hardware-gated — see HARDWARE_TESTING.md.
  * DECOY PLAUSIBILITY (believable decoy contents, hidden-volume deniability so a
    coercer cannot prove a real vault exists behind the decoy) is a UX/loading
    problem, only sketched here (a pre-seeded decoy). True plausible-deniability
    against a coercer who knows the scheme is out of scope for the PoC.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Callable, Optional

from ..crypto.primitives import H, aead_decrypt, aead_encrypt, hkdf, random_bytes
from .vault import Vault

_CODE_INFO = b"atlas/duress/code-key"
_SEAL_AAD_REAL = b"atlas/duress/seal|real"
_SEAL_AAD_DECOY = b"atlas/duress/seal|decoy"


def _code_key(code: bytes, salt: bytes) -> bytes:
    """Derive the sealing key for a passcode. Distinct salts/codes give distinct
    keys, so the panic code cannot unwrap the real key (AEAD fails)."""
    return hkdf(ikm=code, info=_CODE_INFO, salt=salt, length=32)


class VaultZeroized(Exception):
    """The real key material was destroyed by a suspicion event — the real vault
    is a permanent brick and cannot be reopened."""


@dataclass(frozen=True)
class UnlockResult:
    """What the OBSERVER sees vs. what the system does. `surface_ok` is identical
    for the normal and panic paths; `duress` is internal-only, never surfaced."""

    surface_ok: bool
    duress: bool
    vault: Optional[Vault]        # real view (normal) or decoy view (panic)


class PanicVault:
    """Local duress arm: a normal passcode opens the real vault; a panic passcode
    opens a surface-identical decoy while the real key stays sealed; a suspicion
    signal zeroizes the real key.

    The real/decoy storage keys are sealed under passcode-derived keys (modelling
    Enclave seal/release). Neither passcode can unwrap the other's blob.
    """

    def __init__(self, *, normal_code: bytes, panic_code: bytes,
                 on_zeroize: Optional[Callable[[str], None]] = None):
        if hmac.compare_digest(H(b"atlas/duress/code", normal_code),
                               H(b"atlas/duress/code", panic_code)):
            raise ValueError("normal and panic codes must differ")
        self._salt = random_bytes(16)
        self._real_key: Optional[bytes] = random_bytes(32)
        decoy_key = random_bytes(32)
        # Seal each storage key under its own passcode-derived key.
        self._sealed_real: Optional[bytes] = aead_encrypt(
            _code_key(normal_code, self._salt), self._real_key, aad=_SEAL_AAD_REAL)
        self._sealed_decoy: bytes = aead_encrypt(
            _code_key(panic_code, self._salt), decoy_key, aad=_SEAL_AAD_DECOY)
        # Live vaults. The decoy is pre-seeded so it looks used.
        self._real_vault = Vault(self._real_key)
        self._decoy_vault = Vault(decoy_key)
        self._on_zeroize = on_zeroize
        self._zeroized = False

    # -- real-vault authoring (normal owner, out of band) -------------------

    def put_real(self, name: str, plaintext: bytes) -> None:
        if self._zeroized or self._real_key is None:
            raise VaultZeroized("real vault destroyed")
        self._real_vault.put(name, plaintext)

    def seed_decoy(self, name: str, plaintext: bytes) -> None:
        """Pre-seed plausible decoy content (enrolment-time; see honesty note on
        decoy plausibility)."""
        self._decoy_vault.put(name, plaintext)

    # -- unlock -------------------------------------------------------------

    def unlock(self, code: bytes) -> UnlockResult:
        """Try the code against the real seal, then the decoy seal. Normal code ->
        real view; panic code -> decoy view (duress, internal-only); neither ->
        surface failure. Response shape is identical for real vs panic."""
        # Real path (only if not zeroized). Unsealing authenticates the passcode;
        # the returned vault is the live real store keyed by the released key.
        if not self._zeroized and self._sealed_real is not None:
            key = self._try_unseal(code, self._sealed_real, _SEAL_AAD_REAL)
            if key is not None:
                return UnlockResult(surface_ok=True, duress=False, vault=self._real_vault)
        # Panic path -> decoy. Surface-identical to the real path.
        key = self._try_unseal(code, self._sealed_decoy, _SEAL_AAD_DECOY)
        if key is not None:
            return UnlockResult(surface_ok=True, duress=True, vault=self._decoy_vault)
        # Genuine wrong code — ordinary failure, distinct from duress.
        return UnlockResult(surface_ok=False, duress=False, vault=None)

    def _try_unseal(self, code: bytes, sealed: bytes, aad: bytes) -> Optional[bytes]:
        try:
            return aead_decrypt(_code_key(code, self._salt), sealed, aad=aad)
        except Exception:
            return None

    # -- zeroize-on-suspicion ----------------------------------------------

    def zeroize_on_suspicion(self, reason: str = "suspicion") -> None:
        """Destroy the real key material. The real vault entries stay on disk as
        unreadable bricks; there is NO path back to plaintext. Idempotent. The
        decoy remains openable so the device still looks alive to a coercer."""
        if self._real_key is not None:
            # Best-effort scrub of the cached key (Python can't guarantee memory
            # wiping — on device this is the Enclave dropping the key; modelled).
            self._real_key = None
        self._sealed_real = None          # the sealed blob is gone -> unrecoverable
        self._real_vault = None           # drop the live real view
        self._zeroized = True
        if self._on_zeroize is not None:
            self._on_zeroize(reason)

    @property
    def zeroized(self) -> bool:
        return self._zeroized

    def real_brick_at_rest(self, name: str) -> bytes:
        """The real ciphertext still on disk after zeroize — provably unreadable
        (the key is gone). Demonstrates fail-closed at rest."""
        if self._real_vault is not None:
            return self._real_vault.raw_at_rest(name)
        # After zeroize the live view is gone but the persisted bytes would remain
        # on real storage; the point is only that no key exists to read them.
        raise VaultZeroized("real vault view dropped; persisted bytes are keyless bricks")
