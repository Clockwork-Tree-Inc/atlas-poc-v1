"""Phone-only ANTI-BOT proof (Tier 1) + standalone OFFLINE verifier.

A live client answers a FRESH, unpredictable challenge by binding it to a MOTION SUMMARY — a
digest computed on device from the IMU gesture + tap<->IMU coherence + the pooled ("grand total")
entropy — and signs the whole thing. The verifier (no network, no server) checks that the response
is bound to THIS fresh challenge (no replay), is signed by the responder, carries a non-empty
physical-signal summary, and that the challenge is one-shot. That defeats the entire remote-
software-bot / replay class: a program with no physical device to move and no finger to tap cannot
produce a fresh, signed, motion-bearing answer to an unpredictable live challenge.

HONEST BOUNDARY: this proves "not a REMOTE / REPLAY bot". It does NOT by itself defeat a physical
motion RIG (a robot moving a real phone) — that is Tier 2 (motion<->physiology coherence, a
wearable). The on-device signal processing that produces the motion summary from real IMU/tap is
the device seam; here the summary is an opaque digest the protocol binds, and the verifier checks
for its PRESENCE, not for the authenticity of the physics.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Set

from ..crypto.primitives import H, random_bytes
from ..crypto.sign import HybridSigPublic, sign, verify

GESTURE = "gesture"
TAP = "tap"


@dataclass
class Challenge:
    nonce: bytes
    epoch: int
    kind: str = GESTURE


def issue_challenge(epoch: int, kind: str = GESTURE) -> Challenge:
    """A fresh, unpredictable challenge — the client cannot pre-record an answer to it."""
    return Challenge(nonce=random_bytes(16), epoch=epoch, kind=kind)


@dataclass
class Response:
    nonce: bytes             # the challenge nonce this answers (binds to THIS challenge)
    kind: str
    motion_summary: bytes    # device digest of IMU gesture + tap<->IMU coherence + pooled entropy
    public: HybridSigPublic
    sig: bytes = b""

    def body(self) -> bytes:
        return H(b"atlas/antibot/response", self.nonce, self.kind.encode(), self.motion_summary)


def respond(ch: Challenge, motion_summary: bytes, keypair, public: HybridSigPublic) -> Response:
    r = Response(nonce=ch.nonce, kind=ch.kind, motion_summary=motion_summary, public=public)
    r.sig = sign(keypair, r.body())
    return r


class AntiBotVerifier:
    """Standalone OFFLINE verifier (no network / no server). Rejects replay (one-shot nonce),
    unsigned/forged responses, responses to the wrong challenge, and responses with no physical
    signal."""

    def __init__(self) -> None:
        self._seen: Set[bytes] = set()

    def verify(self, response: Response, challenge: Challenge) -> bool:
        if response.nonce != challenge.nonce or response.kind != challenge.kind:
            return False                      # not bound to THIS fresh challenge
        if response.nonce in self._seen:
            return False                      # replay: this challenge was already consumed (one-shot)
        if not response.motion_summary:
            return False                      # no physical signal -> a bare program, not a moved device
        if not verify(response.public, response.body(), response.sig):
            return False                      # not signed by the responder
        self._seen.add(response.nonce)
        return True


# ---------------------------------------------------------------------------
# Shake-to-prove-human challenge (RNG-DERIVED plan + escalating time-lock)
# ---------------------------------------------------------------------------
#
# The human proof is: shake the app-attested phone to hit a target the client
# cannot predict. The target sequence is DERIVED FROM THE FRESH CHALLENGE NONCE
# (issue_challenge's CSPRNG draw), so it can be neither precomputed nor replayed
# — a new nonce yields a new plan every time. A plan is an ordered sequence of
# (direction, count) segments; the user shakes UNTIL each segment's target is
# reached, per direction. Directions raise the bar for a physical rig (it must
# reproduce axis-specific motion, not just any impulse). Repeated failures arm
# an escalating lockout so the gate cannot be brute-forced.

UP_DOWN = "updown"
SIDEWAYS = "sideways"
_DIRECTIONS = (UP_DOWN, SIDEWAYS)


@dataclass(frozen=True)
class ShakeSegment:
    direction: str   # UP_DOWN | SIDEWAYS
    count: int


def derive_shake_plan(nonce: bytes, *, segments: int = 2,
                      min_count: int = 3, max_count: int = 6) -> list[ShakeSegment]:
    """Deterministically derive an unpredictable shake plan from the fresh nonce.

    RNG-derived (the nonce is issue_challenge's OS-CSPRNG draw) so the target
    cannot be precomputed or replayed. Byte-parity with Swift `deriveShakePlan`:
    each segment i takes seed = H("atlas/antibot/shake", nonce, i); byte 0 picks
    the direction, byte 1 picks the count in [min_count, max_count].
    """
    if segments < 1:
        raise ValueError("segments must be >= 1")
    if not (0 <= min_count <= max_count <= 255):
        raise ValueError("require 0 <= min_count <= max_count <= 255")
    span = max_count - min_count + 1
    plan: list[ShakeSegment] = []
    for i in range(segments):
        seed = H(b"atlas/antibot/shake", nonce, bytes([i]))
        direction = _DIRECTIONS[seed[0] % len(_DIRECTIONS)]
        count = min_count + (seed[1] % span)
        plan.append(ShakeSegment(direction=direction, count=count))
    return plan


def shake_plan_digest(plan: list[ShakeSegment]) -> bytes:
    """Canonical digest pinning a whole plan (parity KAT / challenge binding)."""
    parts = [b"atlas/antibot/shake/plan"]
    for seg in plan:
        parts.append(seg.direction.encode())
        parts.append(bytes([seg.count]))
    return H(*parts)


# ---------------------------------------------------------------------------
# Tap-to-prove-human challenge (nonce-derived tap RHYTHM, IMU-detected)
# ---------------------------------------------------------------------------
#
# Alternative to the shake: tap the phone BODY in a challenge rhythm ("tap 3 ·
# pause · tap 2"). A finger tap is a sharp accelerometer spike, so detection is
# crisp and — unlike a shake direction — there is NO ambiguous way to perform it:
# a tap is a tap (fewer false failures, better accessibility). The rhythm is
# DERIVED FROM THE FRESH NONCE like the shake plan, so it cannot be precomputed
# or replayed. Same one-shot verifier + escalating lockout apply. (The phone's
# hardware side button is NOT usable — iOS exposes no app API for it; the IMU
# tap is the physical-button-equivalent the platform actually permits.)

@dataclass(frozen=True)
class TapSegment:
    count: int       # taps in this burst; bursts are separated by a clear pause


def derive_tap_plan(nonce: bytes, *, segments: int = 2,
                    min_taps: int = 2, max_taps: int = 5) -> list[TapSegment]:
    """Deterministically derive an unpredictable tap rhythm from the fresh nonce.

    Byte-parity with Swift `deriveTapPlan`: segment i takes
    seed = H("atlas/antibot/tap", nonce, i); byte 0 picks the burst count in
    [min_taps, max_taps]."""
    if segments < 1:
        raise ValueError("segments must be >= 1")
    if not (0 <= min_taps <= max_taps <= 255):
        raise ValueError("require 0 <= min_taps <= max_taps <= 255")
    span = max_taps - min_taps + 1
    plan: list[TapSegment] = []
    for i in range(segments):
        seed = H(b"atlas/antibot/tap", nonce, bytes([i]))
        plan.append(TapSegment(count=min_taps + (seed[0] % span)))
    return plan


def tap_plan_digest(plan: list[TapSegment]) -> bytes:
    """Canonical digest pinning a whole tap plan (parity KAT / challenge binding)."""
    parts = [b"atlas/antibot/tap/plan"]
    for seg in plan:
        parts.append(bytes([seg.count]))
    return H(*parts)


#: Escalating time-lock: the first LOCK_FREE_TRIES cumulative failures are free;
#: each further failure doubles a 30s base lockout, capped at one hour. Arms the
#: human-proof gate against brute-force / automated retry.
LOCK_FREE_TRIES = 10
_LOCK_BASE_S = 30
_LOCK_CAP_S = 3600


def lock_backoff_seconds(fail_count: int) -> int:
    """Seconds the gate stays locked after `fail_count` cumulative failed attempts.

    fail_count <= 10 -> 0 (free); 11 -> 30, 12 -> 60, 13 -> 120, ... capped at 3600.
    """
    if fail_count <= LOCK_FREE_TRIES:
        return 0
    over = fail_count - LOCK_FREE_TRIES - 1
    return min(_LOCK_BASE_S * (2 ** over), _LOCK_CAP_S)
