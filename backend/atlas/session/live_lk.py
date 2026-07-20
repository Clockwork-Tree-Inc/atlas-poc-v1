"""Two-device co-derived Living Key (LK) — the live LK for the two-phone run.

Replaces the single-device `os.urandom(32)` stub in the two-phone demo. The LK
VALUE is co-derived from BOTH devices' fresh secret contributions: each device
draws a fresh CSPRNG secret and they are combined (HKDF) into the epoch's LK.
Neither device alone controls it (each contribution is independent + secret) and
neither can predict it before the other's contribution is combined —
unpredictable-to-either, controllable-by-neither, bound to the epoch.

INVARIANT (unchanged): only fresh secret VALUES are combined. Timing never enters
the value — drand, if used at all, only paces WHEN a device fires its
contribution, never the bytes. So the LK stays a clean co-derived QRNG/CSPRNG
value. drand is NOT a value input (that was only ever about timing-aggregate
degeneracy, and timing never enters the value).

Both devices exchange contributions over their E2E channel (the blind node never
sees them) and each computes the SAME LK locally: combination is order-independent
(contributions are sorted), so A and B agree with no designated leader.
"""

from __future__ import annotations

from typing import List

from ..crypto.primitives import hkdf_combine, random_bytes

_LK_INFO = b"atlas/live-lk/co-derived"
CONTRIB_BYTES = 32


def device_contribution() -> bytes:
    """A device's fresh secret LK contribution — a clean CSPRNG value. Never a
    function of timing; exchanged only over the E2E channel (node stays blind)."""
    return random_bytes(CONTRIB_BYTES)


def co_derive_lk(contributions: List[bytes], *, drand_round: bytes) -> bytes:
    """Combine >= 2 mutually-unknown device contributions into the epoch LK.

    Order-independent (contributions sorted) so both devices compute the identical
    LK. Raises on < 2 contributions — a live LK is co-derived by definition, never
    single-device.
    """
    if len(contributions) < 2:
        raise ValueError("live LK requires >= 2 device contributions (co-derived, not single-device)")
    ordered = sorted(contributions)
    return hkdf_combine(ordered + [drand_round], info=_LK_INFO, length=32)
