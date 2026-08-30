"""Guardian forensic access — a trusted contact can collect your panic forensics ONLY if BOTH of you
agreed. Consent is enforced by arithmetic, not policy.

The forensic capture is sealed under a `forensic_key`, which is Shamir 2-of-2 split into:
  * a CONTACT share — handed to the trusted contact when they ACCEPT the guardian role (their consent).
  * an OWNER share — kept by you and RELEASED ONLY when panic fires (your consent, in the moment).

Neither share alone opens anything. So the contact can reconstruct `forensic_key` and read your
capture only when they hold their share (they agreed) AND you released yours (you triggered panic) —
"both parties agree" as a 2-of-2, not a promise. A stolen contact-share alone is inert; a foreign
owner's share combined with this contact's share reconstructs a WRONG key that fails to open the
capture (AEAD rejects it) — shares are per-relationship, so cross-pairing collects nothing.

Reference of record. Composes atlas.crypto.shamir + AES-GCM; no new primitive.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from ..crypto import shamir
from ..crypto.primitives import aead_decrypt, aead_encrypt, random_bytes


class GuardianError(Exception):
    """Base — fail-closed."""


class ConsentIncomplete(GuardianError):
    """Collection attempted without BOTH the contact share (accepted) and the owner share (released)."""


@dataclass(frozen=True)
class GuardianGrant:
    """What each side ends up holding after a mutual guardian setup."""
    contact_share: shamir.Share    # given to the trusted contact when they accept (their standing consent)
    owner_share: shamir.Share      # kept by the owner; released to the contact only on panic


def setup_guardian(forensic_key: bytes) -> GuardianGrant:
    """Split the forensic key 2-of-2 at guardian setup. Call when the owner designates a contact AND
    the contact accepts — the contact keeps `contact_share`, the owner keeps `owner_share`."""
    if len(forensic_key) < 16:
        raise ValueError("forensic_key must be >= 16 bytes")
    a, b = shamir.split(forensic_key, n=2, k=2)
    return GuardianGrant(contact_share=a, owner_share=b)


def collect_forensic_key(contact_share: shamir.Share, owner_share: shamir.Share) -> bytes:
    """Reconstruct the forensic key — needs BOTH shares (contact accepted + owner released on panic)."""
    try:
        return shamir.combine([contact_share, owner_share])
    except Exception as e:  # a single share, or a foreign owner's share, yields the wrong/no key
        raise ConsentIncomplete("need BOTH the contact's share and the owner's panic-released share") from e


# Convenience: seal / open the capture itself under the forensic key.
def seal_forensic(forensic_key: bytes, data: bytes, *, aad: bytes = b"atlas/guardian/forensic") -> bytes:
    return aead_encrypt(forensic_key, data, aad=aad)


def open_forensic(forensic_key: bytes, blob: bytes, *, aad: bytes = b"atlas/guardian/forensic") -> bytes:
    return aead_decrypt(forensic_key, blob, aad=aad)


def new_forensic_key() -> bytes:
    return random_bytes(32)
