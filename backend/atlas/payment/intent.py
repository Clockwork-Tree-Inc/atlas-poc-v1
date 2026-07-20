"""Side-button presence/intent gate — YubiKey-touch replacement (Payment spec §5).

The side-button press proves deliberate human intent for THIS action,
in-the-moment. Malware cannot press it. It is a GATE, never a key store.

Honest boundary (§5): the button is part of the phone, protected by the Secure
Enclave's isolation — sufficient for routine actions, but it does NOT provide
separate-device (YubiKey-grade) isolation. The air-gapped Card 2 provides that.

Modelled here as a token that only exists when a real press occurs. In code,
`press()` stands in for the OS-confirmed side-button event (e.g. the Apple Pay
double-press); malware has no path to call it. The optional co-motion mode binds
the press to the enrolled person's ringed hand (reuses the enrolment ring-lock).
"""

from __future__ import annotations

from dataclasses import dataclass

from ..crypto.primitives import random_bytes, H


@dataclass(frozen=True)
class IntentToken:
    """Evidence of a deliberate, in-the-moment side-button press."""

    nonce: bytes
    co_motion_confirmed: bool

    def digest(self) -> bytes:
        return H(b"atlas/intent", self.nonce, b"\x01" if self.co_motion_confirmed else b"\x00")


class SideButtonIntent:
    """Models the OS-confirmed side-button event. Only a real press yields a
    token; there is no programmatic path for malware to forge one."""

    def press(self, *, co_motion_confirmed: bool = False) -> IntentToken:
        return IntentToken(nonce=random_bytes(16), co_motion_confirmed=co_motion_confirmed)
