"""PoLE value — a physiologically-TIMED QRNG value (Locked Model §2.3).

THE PRINCIPLE: value = QRNG (clean); timing/liveness times draws and gates
operations, but NEVER enters a value.

PoLE_value is therefore NOT an un-timed RNG draw and NOT raw physiology. The
enrolled ring's live sensor signal TIMES when the device QRNG fires (the firing
moment within the ratchet window); the fired value is a clean QRNG output. The
physiological signal's only role is scheduling the firing — it never contributes
bytes to the value.
"""

from __future__ import annotations

from typing import Optional

from ..crypto.primitives import random_bytes


def fire_pole_value(*, physio_fire_moment: Optional[float] = None) -> bytes:
    """Fire the device QRNG at a physiologically-timed moment.

    `physio_fire_moment` is WHEN the ring's live signal triggered the fire (a
    schedule input only); it is deliberately NOT used to derive the bytes. Returns
    a clean 32-byte QRNG value = PoLE_value. (Same discipline as the server LK:
    timing determines the firing moment; the value is clean QRNG.)
    """
    # The value is clean QRNG. physio_fire_moment intentionally does not enter it.
    return random_bytes(32)
