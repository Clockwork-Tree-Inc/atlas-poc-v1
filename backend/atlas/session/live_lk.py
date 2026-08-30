"""Two-device co-derived Living Key (LK) — the live LK for the two-phone run.

Replaces the single-device `os.urandom(32)` stub in the two-phone demo. The LK
VALUE is co-derived from BOTH devices' fresh secret contributions: each device
draws a fresh CSPRNG secret and they are combined (HKDF) into the epoch's LK.
Neither device alone controls it (each contribution is independent + secret) and
neither can predict it before the other's contribution is combined —
unpredictable-to-either, controllable-by-neither, bound to the epoch.

INVARIANT: only fresh secret VALUES are combined as key material. The epoch round
is used solely as HKDF domain-separation CONTEXT (`info`), never as a combined
value — so it binds the LK to its epoch without becoming an input to the secret.
External drand is not involved at all here (the epoch round is the aggregator's
QRNG epoch index, not a drand round); timing never enters the value either. So the
LK stays a clean co-derived QRNG/CSPRNG value.

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


def co_derive_lk(contributions: List[bytes], *, epoch_round: bytes) -> bytes:
    """Combine >= 2 mutually-unknown device contributions into the epoch LK.

    Order-independent (contributions sorted) so both devices compute the identical
    LK. Raises on < 2 contributions — a live LK is co-derived by definition, never
    single-device. `epoch_round` (the aggregator's QRNG epoch index) is used only
    as domain-separation context, binding the LK to its epoch without entering the
    combined secret.
    """
    if len(contributions) < 2:
        raise ValueError("live LK requires >= 2 device contributions (co-derived, not single-device)")
    ordered = sorted(contributions)
    return hkdf_combine(ordered, info=_LK_INFO + epoch_round, length=32)
