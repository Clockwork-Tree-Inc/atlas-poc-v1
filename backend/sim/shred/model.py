"""Core reference model for UNLINK (re-root) and DELETE (crypto-shred).

Everything here is deliberately small and faithful to the real Atlas derivations
so the property tests exercise the *same shape* of construction that ships in
backend/atlas, not a toy stand-in.

Faithfulness anchors
--------------------
* `System.pseudonym` uses the SAME HKDF-from-System-ID construction as
  `atlas.keys.identity.IdentityTree.pseudonym` — a per-(generation, context)
  PRF over the blind System-ID secret.
* `System.reroot` mirrors `atlas.realid.rerooting.reroot_system_id`: the durable
  root (TSK seed) is UNCHANGED; only the System-ID generation salt advances, so
  the entire pseudonym set rotates and the new generation is unlinkable from the
  old. Re-rooting is holder-authority gated (no operator path).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from atlas.crypto.primitives import H, hkdf, aead_encrypt, aead_decrypt, random_bytes


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class OperatorForbidden(Exception):
    """Re-rooting / erasure is holder-authority only — no operator path."""


class Shredded(Exception):
    """The secret opening was destroyed; the operation is now impossible."""


# ---------------------------------------------------------------------------
# System-ID  ->  per-(generation, context) pseudonyms   (mirrors identity.py)
# ---------------------------------------------------------------------------

def _system_id_secret(tsk_seed: bytes, *, generation: int) -> bytes:
    """Blind System-ID secret for a re-root generation.

    Mirrors atlas: the durable TSK seed is constant across re-roots; a
    generation salt (rotation) advances so the System-ID — and therefore every
    forward-derived pseudonym — rotates to an unlinkable value.
    """
    salt = b"" if generation == 0 else b"/v" + str(generation).encode()
    return hkdf(ikm=tsk_seed, info=b"atlas/sim/system-id" + salt, length=32)


@dataclass
class System:
    """A user's live identity material. Holds the blind System-ID secret for the
    current generation and can forward-derive pseudonyms. Never surfaces the
    secret; only opaque handles leave the object."""

    tsk_seed: bytes = field(repr=False)
    generation: int = 0
    _secret: bytes = field(repr=False, default=b"")

    def __post_init__(self) -> None:
        if not self._secret:
            self._secret = _system_id_secret(self.tsk_seed, generation=self.generation)

    @classmethod
    def enroll(cls) -> "System":
        """Genesis: a fresh, independent identity from a QRNG-style random TSK."""
        return cls(tsk_seed=random_bytes(32), generation=0)

    def system_id_handle(self) -> bytes:
        """Opaque handle of the blind System-ID (the secret is never exposed)."""
        return H(b"atlas/sim/system-id-handle", self._secret)

    def pseudonym(self, context: str) -> bytes:
        """Forward-derive the pseudonym handle for a context (PRF over the blind
        System-ID). Same construction as IdentityTree.pseudonym. Distinct context
        or generation -> distinct, mutually unlinkable handle."""
        return H(b"atlas/sim/pseudonym",
                 hkdf(ikm=self._secret,
                      info=b"atlas/sim/pseudonym/" + context.encode(),
                      length=32))

    def reroot(self, *, user_authorized: bool) -> "System":
        """Forward-heal: advance to a fresh System-ID generation. The durable
        TSK seed is unchanged; only the generation salt advances. Holder-authority
        only — there is NO operator path (mirrors reroot_system_id §6)."""
        if not user_authorized:
            raise OperatorForbidden(
                "re-rooting requires the user's own authority (no operator path)")
        return System(tsk_seed=self.tsk_seed, generation=self.generation + 1)


# ---------------------------------------------------------------------------
# Append-only registry of COMMITMENTS (never raw data)
# ---------------------------------------------------------------------------

@dataclass
class RegistryEntry:
    """One append-only row. Stores ONLY a hiding commitment and an AEAD-sealed
    blob whose key is the user's. No raw System-ID or pseudonym is stored.

    * `commitment` = H(domain, system_id_secret, opening_nonce): binding+hiding.
      Opening/linking it requires BOTH the System-ID secret AND the opening
      nonce — the user's secret opening.
    * `sealed` = AES-256-GCM(record_key, plaintext) where record_key is derived
      from the opening. The plaintext (which may name the System-ID / pseudonym)
      is recoverable only with the opening.

    Crypto-shred destroys the opening, leaving both fields as inert bytes.
    """

    commitment: bytes
    sealed: bytes                       # nonce || ct||tag  (AES-256-GCM)
    row_id: int = 0


class Registry:
    """Append-only. `append` adds a row; there is deliberately NO delete/mutate
    method — erasure can only be achieved cryptographically (destroy the opening),
    never by removing the row."""

    def __init__(self) -> None:
        self._rows: List[RegistryEntry] = []

    def append(self, entry: RegistryEntry) -> int:
        entry.row_id = len(self._rows)
        self._rows.append(entry)
        return entry.row_id

    def __len__(self) -> int:
        return len(self._rows)

    def get(self, row_id: int) -> RegistryEntry:
        return self._rows[row_id]

    def rows(self) -> List[RegistryEntry]:
        return list(self._rows)


# ---------------------------------------------------------------------------
# The user's secret OPENING  +  enrolment / crypto-shred
# ---------------------------------------------------------------------------

_COMMIT_DOMAIN = b"atlas/sim/registry-commitment"
_RECORDKEY_INFO = b"atlas/sim/registry-record-key"


@dataclass
class Opening:
    """The user-held secret that opens a registry row: the System-ID secret plus
    a high-entropy per-row nonce. Destroying it crypto-shreds the row.

    In deployment this lives only in the user's card/enclave; the registry never
    sees it."""

    system_id_secret: bytes = field(repr=False)
    nonce: bytes = field(repr=False)
    _alive: bool = True

    def destroy(self) -> None:
        """Right-to-erasure: irrecoverably destroy the opening. Overwrite then
        drop the references (models zeroization; Python cannot guarantee memory
        wiping, an honest boundary shared with the real enclave model)."""
        self.system_id_secret = b"\x00" * len(self.system_id_secret)
        self.nonce = b"\x00" * len(self.nonce)
        self.system_id_secret = b""
        self.nonce = b""
        self._alive = False

    @property
    def alive(self) -> bool:
        return self._alive


def _record_key(system_id_secret: bytes, nonce: bytes) -> bytes:
    return hkdf(ikm=system_id_secret + nonce, info=_RECORDKEY_INFO, length=32)


def _commitment(system_id_secret: bytes, nonce: bytes) -> bytes:
    return H(_COMMIT_DOMAIN, system_id_secret, nonce)


def enroll_in_registry(system: System, registry: Registry, plaintext: bytes) -> tuple[int, Opening]:
    """Persist a commitment for `system` into the append-only registry.

    Returns the row id and the user's secret Opening. The registry stores only
    the hiding commitment and the AEAD-sealed blob; the opening stays with the
    user. `plaintext` stands in for whatever the row attests (it may reference
    the System-ID / a pseudonym) — it is sealed, never stored in the clear."""
    nonce = random_bytes(32)
    opening = Opening(system_id_secret=system._secret, nonce=nonce)
    commitment = _commitment(system._secret, nonce)
    record_key = _record_key(system._secret, nonce)
    sealed = aead_encrypt(record_key, plaintext, aad=commitment)
    row = RegistryEntry(commitment=commitment, sealed=sealed)
    row_id = registry.append(row)
    return row_id, opening


def open_row(registry: Registry, row_id: int, opening: Opening) -> bytes:
    """Open (decrypt) a registry row with the user's secret opening. Fails once
    the opening has been crypto-shredded."""
    if not opening.alive:
        raise Shredded("opening destroyed — row is an unlinkable orphan")
    row = registry.get(row_id)
    record_key = _record_key(opening.system_id_secret, opening.nonce)
    return aead_decrypt(record_key, row.sealed, aad=row.commitment)


def links_with_opening(registry: Registry, row_id: int, opening: Opening,
                       system: System) -> bool:
    """Full-secret resolver: with BOTH the opening and the System-ID, confirm the
    row commits to this System-ID. This is the only path that links a row to a
    user, and it dies the moment the opening is shredded."""
    if not opening.alive:
        return False
    row = registry.get(row_id)
    return _commitment(system._secret, opening.nonce) == row.commitment
