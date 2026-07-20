"""hardened.py — make the secret-nonce rule STRUCTURAL, not a convention.

The base crypto-shred model (`sim.shred.model`) proves that destroying a
high-entropy secret opening realises right-to-erasure on an append-only log.
But that guarantee is only as strong as the weakest commitment ever written:
if ANY row could be registered with a *deterministic* opening — e.g. a plain
``H(System-ID)`` with no secret nonce — that row would stay linkable forever,
and no amount of shredding elsewhere would help. The base ``RegistryEntry`` /
``Registry.append`` pair does not prevent this: a caller can hand-build an
entry around a low-entropy commitment and append it.

This module CLOSES that gap by construction. The ONLY public path that writes to
the log — :meth:`HardenedRegistry.register` — takes just ``(system, plaintext)``
and generates a fresh 256-bit secret nonce *internally*. There is no public
method, and no parameter on any public method, through which a caller can inject
a commitment, a nonce, or an opening. It is therefore structurally impossible to
register a non-erasable (deterministic / linkable) commitment through the API,
even by mistake. Shredding is then exactly: destroy the returned opening.

Two inherent limits of an append-only log are handled honestly:

  * ROW EXISTENCE + INSERT TIMING metadata cannot be erased. We do NOT pretend
    to. We DO close the timing side as far as a registry can: rows may be
    committed via a batched / rotated write, so every row in a batch shares one
    insert timestamp and is committed in shuffled order — decorrelating insert
    time/order from registration time/order.

  * CONTENT ALREADY DISCLOSED TO A THIRD PARTY lives outside any registry and
    cannot be recalled. It is explicitly OUT OF SCOPE here — it is never stored
    in the registry, so there is nothing for the registry to erase or leak.

Reuses the real Atlas primitives (`atlas.crypto.primitives`) and the append-only
`Registry` / `RegistryEntry` / commitment construction from `sim.shred.model`.
"""

from __future__ import annotations

import inspect
import random
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from atlas.crypto.primitives import (
    H,
    aead_encrypt,
    aead_decrypt,
    random_bytes,
)

# Reuse the *exact* append-only log and commitment construction from the model —
# nothing here re-implements the crypto; it only removes the misuse surface.
from sim.shred.model import (
    System,
    Registry,
    RegistryEntry,
    Shredded,
    _commitment,
    _record_key,
)


# The secret that gets destroyed. 256 bits — far beyond any brute-force reach and
# the sole reason a shredded commitment is unlinkable even to someone who still
# holds the System-ID secret.
NONCE_BITS = 256
_NONCE_BYTES = NONCE_BITS // 8
_TOKEN_BYTES = 16


class RegistrationError(Exception):
    """Raised on any attempt to smuggle caller-controlled opening material into
    the one legitimate registration path."""


# ---------------------------------------------------------------------------
# The user's secret opening — mutable buffers so destroy() provably zeroizes.
# ---------------------------------------------------------------------------

class SecureOpening:
    """User-held secret opening (System-ID secret + fresh nonce), stored in
    mutable ``bytearray`` buffers so :meth:`destroy` overwrites the key material
    in place and the caller can *assert* it was zeroed.

    In deployment this lives only in the user's card/enclave; the registry never
    sees it. It is constructed exclusively by :meth:`HardenedRegistry.register`."""

    __slots__ = ("_sid", "_nonce", "_alive")

    def __init__(self, system_id_secret: bytes, nonce: bytes) -> None:
        if len(nonce) != _NONCE_BYTES:
            # The registry always passes a full-entropy nonce; a short one would
            # be a bug, so refuse it rather than silently weaken erasure.
            raise RegistrationError(
                f"opening nonce must be {_NONCE_BYTES} bytes of entropy")
        self._sid = bytearray(system_id_secret)
        self._nonce = bytearray(nonce)
        self._alive = True

    @property
    def alive(self) -> bool:
        return self._alive

    def _material(self) -> Tuple[bytes, bytes]:
        if not self._alive:
            raise Shredded("opening destroyed — row is an unlinkable orphan")
        return bytes(self._sid), bytes(self._nonce)

    def buffers(self) -> Tuple[bytearray, bytearray]:
        """The live backing buffers — exposed so zeroization can be asserted."""
        return self._sid, self._nonce

    def destroy(self) -> None:
        """Right-to-erasure: overwrite the key buffers with zeros IN PLACE, then
        mark dead. The bytearrays keep their length so the test can confirm every
        byte is 0x00 (an honest model of enclave zeroization; Python still cannot
        guarantee no copy lingered elsewhere in memory)."""
        for buf in (self._sid, self._nonce):
            for i in range(len(buf)):
                buf[i] = 0
        self._alive = False


# ---------------------------------------------------------------------------
# Opaque receipt — locates a row without leaking anything linkable.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Receipt:
    """Opaque locator returned to the user by :meth:`HardenedRegistry.register`.
    Carries a random token, never a commitment or opening — on its own it reveals
    nothing and links to nothing."""

    token: bytes = field(repr=False)

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"Receipt({self.token[:4].hex()}..)"


# ---------------------------------------------------------------------------
# The hardened registry — register() is the ONLY write path.
# ---------------------------------------------------------------------------

def _default_clock() -> Callable[[], int]:
    """A monotonic virtual clock (deterministic, injectable for tests)."""
    t = 0

    def now() -> int:
        nonlocal t
        v = t
        t += 1
        return v

    return now


class HardenedRegistry:
    """Append-only registry whose sole public registration path generates the
    secret opening itself.

    Design invariants (enforced structurally, checked by the property tests):

      * ``register(system, plaintext)`` is the ONLY public method that appends to
        the log, and its signature admits no commitment / nonce / opening
        parameter — so a caller cannot register a deterministic commitment.
      * Each call draws a FRESH 256-bit nonce internally; two identical
        ``(system, plaintext)`` inputs therefore yield different commitments.
      * The underlying append-only log is private; there is no public delete or
        mutate — erasure is only ever cryptographic (destroy the opening).

    ``batched=True`` commits rows via a rotated batch write to decorrelate insert
    timing from registration timing.
    """

    def __init__(
        self,
        *,
        batched: bool = False,
        clock: Optional[Callable[[], int]] = None,
        rng: Optional[random.Random] = None,
    ) -> None:
        self._log = Registry()                       # reused append-only log
        self._batched = batched
        self._clock = clock or _default_clock()
        self._rng = rng or random.Random(int.from_bytes(random_bytes(8), "big"))
        self._token_rowid: Dict[bytes, int] = {}
        self._request_time: Dict[bytes, int] = {}
        self._insert_time: Dict[int, int] = {}
        self._insert_order: Dict[int, int] = {}      # append seq -> monotonic
        self._insert_seq = 0
        # staged, not-yet-committed rows for the batched write path
        self._pending: List[Tuple[bytes, RegistryEntry]] = []

    # -- the one and only registration path ---------------------------------

    def register(self, system: System, plaintext: bytes) -> Tuple[Receipt, SecureOpening]:
        """Persist a commitment for ``system`` and return an opaque receipt plus
        the user's fresh secret opening.

        A full-entropy nonce is drawn HERE — the caller has no way to supply,
        influence, or predict it — so the commitment is always hiding and always
        crypto-shreddable. ``plaintext`` (which may name the System-ID / a
        pseudonym) is AEAD-sealed under a key derived from the opening; it is
        never stored in the clear."""
        request_time = self._clock()
        token = random_bytes(_TOKEN_BYTES)

        sid_secret = system._secret
        nonce = random_bytes(_NONCE_BYTES)           # <-- internal, high-entropy
        opening = SecureOpening(sid_secret, nonce)

        commitment = _commitment(sid_secret, nonce)
        record_key = _record_key(sid_secret, nonce)
        sealed = aead_encrypt(record_key, plaintext, aad=commitment)
        entry = RegistryEntry(commitment=commitment, sealed=sealed)

        self._request_time[token] = request_time
        if self._batched:
            self._pending.append((token, entry))     # committed later, shuffled
        else:
            self._commit(token, entry, insert_time=request_time)

        return Receipt(token), opening

    # -- batched / rotated write (timing-metadata mitigation) ----------------

    def flush(self) -> int:
        """Commit all staged rows in a single rotated batch: shuffled order, one
        shared insert timestamp. Returns the number of rows committed."""
        if not self._pending:
            return 0
        batch_time = self._clock()                   # one rotated time for all
        order = list(range(len(self._pending)))
        self._rng.shuffle(order)                      # decorrelate insert order
        for idx in order:
            token, entry = self._pending[idx]
            self._commit(token, entry, insert_time=batch_time)
        n = len(self._pending)
        self._pending = []
        return n

    def _commit(self, token: bytes, entry: RegistryEntry, *, insert_time: int) -> int:
        row_id = self._log.append(entry)             # reuse append-only semantics
        self._token_rowid[token] = row_id
        self._insert_time[row_id] = insert_time
        self._insert_order[row_id] = self._insert_seq
        self._insert_seq += 1
        return row_id

    # -- read paths (require the opening) ------------------------------------

    def _row_id(self, receipt: Receipt) -> int:
        if receipt.token not in self._token_rowid:
            raise KeyError("receipt not yet committed — call flush()")
        return self._token_rowid[receipt.token]

    def open(self, receipt: Receipt, opening: SecureOpening) -> bytes:
        """Decrypt a row with the user's opening. Dies once the opening is
        shredded."""
        sid, nonce = opening._material()             # raises Shredded if dead
        row = self._log.get(self._row_id(receipt))
        return aead_decrypt(_record_key(sid, nonce), row.sealed, aad=row.commitment)

    def links(self, receipt: Receipt, opening: SecureOpening, system: System) -> bool:
        """Full-secret resolver: confirm the row commits to this System-ID. The
        only link path, and it dies the moment the opening is shredded."""
        if not opening.alive:
            return False
        sid, nonce = opening._material()
        row = self._log.get(self._row_id(receipt))
        return _commitment(system._secret, nonce) == row.commitment

    def stored_row(self, receipt: Receipt) -> RegistryEntry:
        """The raw persisted row (commitment + sealed blob). Remains forever,
        even after shred — this is the append-only guarantee."""
        return self._log.get(self._row_id(receipt))

    # -- metadata (honest: this is what an observer of the log can see) -------

    def request_time(self, receipt: Receipt) -> int:
        return self._request_time[receipt.token]

    def insert_time(self, receipt: Receipt) -> int:
        return self._insert_time[self._row_id(receipt)]

    def insert_order(self, receipt: Receipt) -> int:
        return self._insert_order[self._row_id(receipt)]

    def __len__(self) -> int:
        return len(self._log)


# ---------------------------------------------------------------------------
# Introspection helper used by Property 1 to prove the API is misuse-proof.
# ---------------------------------------------------------------------------

_INJECTION_WORDS = ("commitment", "nonce", "opening", "sealed", "entry",
                    "secret", "digest", "key")


def public_write_surface() -> Dict[str, List[str]]:
    """Map every PUBLIC method of HardenedRegistry to its parameter names.

    Used to demonstrate, by inspection, that no public method exposes a parameter
    through which a caller could inject opening material (a low-entropy nonce, a
    hand-built commitment, an opening, ...)."""
    surface: Dict[str, List[str]] = {}
    for name, member in inspect.getmembers(HardenedRegistry, inspect.isfunction):
        if name.startswith("_"):
            continue                                 # private by convention
        params = [p for p in inspect.signature(member).parameters if p != "self"]
        surface[name] = params
    return surface
