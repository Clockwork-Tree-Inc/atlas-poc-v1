"""First-contact bootstrap — be FINDABLE without pinning down a mailbox.

A findable persona never publishes a standing inbox. Instead:

  * ROTATING CONNECT CODE — a short beacon-clocked code (TOTP-style, like the mailbox rotation) derived
    from a per-persona secret and the current beacon epoch. You share the CURRENT code (scan/tap in
    person); it changes every epoch, with a small catch-up window for skew, so a harvested code dies.

  * RENDEZVOUS — a rotating first-contact drop, NOT a mailbox. For an OPEN persona it is derived from
    the persona's public key + epoch (anyone who resolved the nameplate can knock). For a CODE_ONLY
    persona it is derived from the CONNECT CODE + epoch, so only someone you handed a code to can even
    find the drop. Either way it rotates each epoch and holds no standing address.

A stranger seals a KNOCK to the persona's KEM key (via crypto.kem, exactly as the relay's sealed-sender)
and drops it at the rendezvous. The persona polls its rendezvous, sees the caller id (a caller-ID ring),
and ACCEPTS or rejects. Only on accept does the shared secret promote to a per-pair `pair_secret`, after
which all traffic uses the rotating pair mailbox (net.privacy.mailbox) — fully unlinkable. This module
is the code/rendezvous/gate core; the KEM seal and the pair mailbox are the existing primitives it
composes. Swift parity in Contact.swift.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Set

from ...crypto.primitives import H, hkdf
from .mailbox import MAILBOX_BYTES, catch_up_epochs, epoch_for_round

CODE_DIGITS = 8   # an 8-digit beacon-clocked code, like a passkey/TOTP


class ContactMode(Enum):
    OPEN = "open"                    # anyone who resolved the nameplate may knock
    CODE_ONLY = "code-only"          # only someone holding a current connect code may knock
    CONTACTS_ONLY = "contacts-only"  # only already-accepted contacts
    CLOSED = "closed"                # no knocks


# --- rotating connect code -------------------------------------------------

def connect_code(code_secret: bytes, epoch: bytes) -> str:
    """The beacon-clocked code for one epoch: 8 digits from H(secret, epoch). Rotates every epoch."""
    n = int.from_bytes(H(b"atlas/connect-code/v1", code_secret, epoch)[:8], "big") % (10 ** CODE_DIGITS)
    return f"{n:0{CODE_DIGITS}d}"


def current_code(code_secret: bytes, now_round: int) -> str:
    return connect_code(code_secret, epoch_for_round(now_round))


def code_valid(code_secret: bytes, code: str, now_round: int, *, window: int = 2) -> bool:
    """Accept a code that matches the current epoch or one within the catch-up window (clock skew /
    a code handed over a few epochs ago). Outside the window it is dead."""
    return any(_ct_eq(connect_code(code_secret, e), code) for e in catch_up_epochs(now_round, window=window))


def _ct_eq(a: str, b: str) -> bool:
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= ord(x) ^ ord(y)
    return diff == 0


# --- rotating rendezvous (a knock-spot, never a mailbox) -------------------

def open_rendezvous(persona_pub_enc: bytes, epoch: bytes) -> bytes:
    """OPEN persona's first-contact drop: derivable by anyone holding the persona's public key."""
    return H(b"atlas/rendezvous-open/v1", persona_pub_enc, epoch)[:MAILBOX_BYTES]


def code_rendezvous(code: str, epoch: bytes) -> bytes:
    """CODE_ONLY persona's drop: derivable only from a valid connect code (which the persona can also
    recompute from its secret). Someone without a code cannot even find where to knock."""
    return H(b"atlas/rendezvous-code/v1", code.encode(), epoch)[:MAILBOX_BYTES]


# --- the accept gate + promotion ------------------------------------------

@dataclass
class KnockDecision:
    allowed: bool
    caller: Optional[bytes]      # the caller's persona public key (caller-ID), when a knock is opened
    reason: str


def gate_knock(mode: ContactMode, *, caller_pub_enc: bytes, presented_code: Optional[str],
               code_secret: bytes, now_round: int, known_contacts: Set[bytes], window: int = 2) -> KnockDecision:
    """Decide whether an opened knock may ring: OPEN always; CODE_ONLY needs a valid current code;
    CONTACTS_ONLY needs an already-accepted caller; CLOSED never. The persona still chooses accept /
    reject after this (the caller-ID ring)."""
    if mode is ContactMode.OPEN:
        return KnockDecision(True, caller_pub_enc, "open")
    if mode is ContactMode.CODE_ONLY:
        ok = presented_code is not None and code_valid(code_secret, presented_code, now_round, window=window)
        return KnockDecision(ok, caller_pub_enc if ok else None, "code-ok" if ok else "code-invalid")
    if mode is ContactMode.CONTACTS_ONLY:
        ok = caller_pub_enc in known_contacts
        return KnockDecision(ok, caller_pub_enc if ok else None, "known" if ok else "not-a-contact")
    return KnockDecision(False, None, "closed")


def promote_pair_secret(shared: bytes) -> bytes:
    """On accept, the KEM shared secret from the knock becomes the per-pair secret that seeds the
    rotating pair mailbox (mailbox.derive_mailbox). Distinct info from any first-contact use of `shared`."""
    return hkdf(ikm=shared, info=b"atlas/contact/pair-secret/v1")
