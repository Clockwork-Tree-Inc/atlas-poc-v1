"""The Epoch beacon — Atlas's OWN public beacon, i.e. the epoch key (§3.2, XV §2.2).

The public epoch key is NOT external drand. It is the QRNG epoch value the LKG
aggregator fires when Living Keys arrive from the collector nodes:

  * Living Keys (LKs) are network-wide secrets, each sealed in SE/HSM throughout
    the whole system. No one, under any circumstance, sees an LK; the ONLY party
    that observes them is the LKG aggregator, and even it consumes only their
    ARRIVALS, never the secret values.
  * The aggregate ARRIVAL TIMING of LKs reaching the aggregator TIMES the firing
    of the QRNG (§2.3: timing times the firing, it NEVER enters the value). So the
    epoch advances on a RANDOM CADENCE, not a fixed period.
  * Each firing publishes a fresh CLEAN-QRNG epoch value with a monotonic epoch
    index, signed by the aggregator so any device can verify authenticity.

External drand (`drand.py` / `local_beacon.py`) is NOT the epoch key. It serves
two bounded roles only:
  * BOOTSTRAP — a public timeline before enough LKs exist to fire the aggregator.
  * DEFENCE-IN-DEPTH ANCHOR — an independent public value recorded ALONGSIDE the
    epoch (bound into the signature, never into the epoch VALUE) so the epoch
    cannot be back-dated and Atlas's own beacon cannot be dismissed as
    self-fabricated.

The 8-byte epoch index returned by `EpochRound.epoch_round()` is the public round
identifier the rest of the protocol uses as its freshness / domain-separation
label. (It was historically threaded under the misnomer `drand_round`, which
wrongly implied external drand was the epoch key.)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..crypto.primitives import H
from ..crypto.sign import HybridSigKeypair, HybridSigPublic, sign, verify
from .qrng import ArrivalTiming, ServerQRNG


@dataclass(frozen=True)
class EpochRound:
    """One published epoch of the public beacon (the epoch key).

    `epoch`       — the monotonic epoch index (advances once per QRNG firing).
    `randomness`  — the CLEAN QRNG epoch value (a function of the fresh entropy
                    core only; never of timing, never of the drand anchor).
    `anchor`      — OPTIONAL external-drand round bytes, recorded for bootstrap /
                    defence-in-depth and bound into `signature`, NEVER into
                    `randomness`.
    `signature`   — the aggregator's signature over (epoch, randomness, anchor);
                    empty for the unsigned PoC stand-in.
    """

    epoch: int
    randomness: bytes
    anchor: bytes = b""
    signature: bytes = b""

    def epoch_round(self) -> bytes:
        """The 8-byte epoch index — the public round identifier used as the
        freshness / domain-separation label throughout the protocol."""
        return self.epoch.to_bytes(8, "big")


def epoch_signing_message(epoch: int, randomness: bytes, anchor: bytes) -> bytes:
    """The message the aggregator signs to publish an epoch. Binding the drand
    `anchor` here (not into the value) is what makes it defence-in-depth: a
    verifier can confirm the epoch was published no earlier than that drand round,
    while the epoch value stays a clean QRNG output."""
    return H(b"atlas/epoch/v1", epoch.to_bytes(8, "big"), randomness, anchor)


class EpochBeacon:
    """The LKG aggregator's public epoch beacon (the source of the epoch key).

    `fire()` is called when a batch of LK arrivals is observed at the aggregator:
    the arrival timing TIMES the firing (random cadence), the QRNG emits a fresh
    clean epoch value, the epoch index advances, and — if configured with a
    signing key — the aggregator signs the round. Pass `anchor` to fold an
    external-drand round in for bootstrap / defence-in-depth.
    """

    def __init__(self, *, signer: Optional[HybridSigKeypair] = None,
                 qrng: Optional[ServerQRNG] = None) -> None:
        self._signer = signer
        self._qrng = qrng or ServerQRNG()
        self._epoch = 0
        self._last: Optional[EpochRound] = None

    @property
    def public(self) -> Optional[HybridSigPublic]:
        """The aggregator verification key (None when running unsigned)."""
        return self._signer.public if self._signer is not None else None

    def fire(self, lk_arrivals: ArrivalTiming, *, anchor: bytes = b"",
             entropy_core: bytes | None = None) -> EpochRound:
        """Advance the epoch, driven by aggregate LK-arrival timing. `entropy_core`
        is injectable ONLY for tests that hold the core constant; production draws
        a fresh QRNG core each firing."""
        self._epoch += 1
        draw = self._qrng.fire(lk_arrivals, anchor, entropy_core=entropy_core)
        randomness = draw.randomness  # CLEAN QRNG value (the anchor is not folded in)
        signature = b""
        if self._signer is not None:
            signature = sign(self._signer, epoch_signing_message(self._epoch, randomness, anchor))
        rnd = EpochRound(epoch=self._epoch, randomness=randomness, anchor=anchor, signature=signature)
        self._last = rnd
        return rnd

    def latest(self) -> EpochRound:
        if self._last is None:
            raise RuntimeError("epoch beacon has not fired yet")
        return self._last


def verify_epoch_round(rnd: EpochRound, pub: HybridSigPublic) -> bool:
    """Verify the aggregator's signature over an epoch round — fail-closed on a
    missing or invalid signature. This is the epoch-beacon analogue of
    `beacon.drand.verify_drand_signature`; the two are independent, so a verifier
    can require BOTH (epoch authenticity AND the drand anchor) as defence-in-depth."""
    if not rnd.signature:
        return False
    return verify(pub, epoch_signing_message(rnd.epoch, rnd.randomness, rnd.anchor), rnd.signature)
