"""Protocol parameters and the resolved §3.2 / §22.1 build-gating decisions.

The spec defers a handful of protocol-mechanics decisions that must be frozen
before an audit (§3.2, §22.1). The user elected to ship documented PoC
defaults; this module is the single source of truth for them so they can be
overridden in one place.

Each default below cites the spec clause that motivates it.
"""

from dataclasses import dataclass


# ---------------------------------------------------------------------------
# §3.2 / §22.1 — resolved build-gating decisions (PoC defaults)
# ---------------------------------------------------------------------------

#: Decision 1 — CORRECTED by the Locked Model §2.3 one-principle (timing NEVER
#: enters a value). The aggregate inter-arrival timing TIMES *when* the QRNG
#: fires (the firing schedule / next-sampling offset), but the fired LK value is
#: CLEAN QRNG — the timing digest is NOT folded into the value bytes. Forward
#: secrecy comes from the fresh QRNG core per firing plus the ratchet chain, not
#: from committing timing into the value. (Was: COMMITTED-into-value; that mixed
#: timing into a value and is now removed — see beacon/qrng.py.)
COMMIT_INTERARRIVAL_TIMING = False

#: Decision 2 (§3.2): "tunnel rooted jointly in both devices (symmetric) or one
#: side leads." -> SYMMETRIC. Recognition is a key-agreement between the two
#: live session keys; neither device leads (see session/recognition.py).
TUNNEL_ROOTING = "symmetric"  # {"symmetric", "leader"}

#: Decision 3 (§3.2): "server returns timed randomness and each device composes
#: its session key locally (server never holds a finished session key)." ->
#: enforced structurally: Device.compose_session_key() runs on the device and
#: the server (qrng) only ever returns a timed entropy draw.
SERVER_RETURNS_TIMED_RANDOMNESS_ONLY = True

#: Decision 4 (§3.2): recognition-window width epsilon. Two devices are
#: considered "currently present together" if their epoch indices match and
#: their locally observed beacon arrival times fall within this window.
RECOGNITION_WINDOW_EPSILON_S = 2.0

#: Decision 5 (§3.2 / §4): epoch length floor/cap — the replay window. The
#: recognition value is constant within an epoch (replayable until the beacon
#: advances), so a max epoch duration forces a re-key if the beacon stalls.
#: NOTE: this is the BEACON clock (public drand epoch key + population Living
#: Key), NOT the device's ratchet clock. The device does not wake on this floor;
#: it consumes the latest cached beacon at its own ratchet tick (see below).
EPOCH_LENGTH_FLOOR_S = 3.0
EPOCH_LENGTH_CAP_S = 30.0


# ---------------------------------------------------------------------------
# Device continuity-ratchet clock (§5.3) — INDEPENDENT of the two beacon clocks
# ---------------------------------------------------------------------------
#
# Three clocks (decoupled):
#   1. Device clock      — local, free-running; drives the continuity ratchet.
#   2. Population LK clock — server secure-element hidden key (private beacon).
#   3. Public epoch clock — drand round (public beacon).
#
# Only clock 1 lives on the phone. Each clock runs its OWN independent schedule
# and consumes each beacon FRESH as it fires — NO caching (§18). Every clock =
# a regular base period + BIOLOGICAL jitter (§16); the jitter source is the live
# signal (device: enrolled ring sample; LK: aggregate PoLE-arrival timing; epoch:
# aggregate LK cadence), NEVER an RNG and NEVER a fixed schedule. The biological
# signal only TIMES the firing (a schedule offset); it never enters a value.
#
# Locked clock model (all bounded — base period is the rail; freshness gradient
# tightest at the device/action level):
#   * device ratchet   10s +- 2    (jitter = enrolled ring signal)
#   * LK (LKG)          30s +- 5    (jitter = aggregate PoLE-arrival timing, server)
#   * epoch key         ~per minute (jitter = aggregate LK cadence, server)
# A missing/stale beacon at a tick makes the device INERT (fail-closed), never
# a fall back to a cached value.

#: Nominal device continuity-ratchet period (the base-period rail).
RATCHET_NOMINAL_S = 10.0
#: Half-width of the biological jitter band: interval in [nominal +- jitter].
#: Default +-2s (8-12s). Must stay < nominal so intervals are always positive. The
#: offset within the band is timed by the enrolled ring's live signal (NOT an RNG).
RATCHET_JITTER_S = 2.0


# ---------------------------------------------------------------------------
# Liveness gate (§5.2)
# ---------------------------------------------------------------------------

#: Operating threshold pi* — operate only if P(L|S) >= PI_STAR (§5.2).
PI_STAR = 0.95

#: Beta(a0, b0) prior on P(L) at enrolment, refined during the calibration
#: window (§6 "Calibration window").
LIVENESS_PRIOR_A0 = 2.0
LIVENESS_PRIOR_B0 = 1.0


# ---------------------------------------------------------------------------
# Cryptographic context separators (§2.3)
# ---------------------------------------------------------------------------

CONTEXT_STORAGE = b"atlas/storage"
CONTEXT_RECOGNITION = b"atlas/recognition"
CONTEXT_TUNNEL = b"atlas/tunnel"

#: Domain-separation labels for the hybrid primitives.
LABEL_XWING = b"atlas/x-wing/v1"
LABEL_RATCHET = b"atlas/ratchet/v1"
LABEL_SESSION = b"atlas/session/v1"


@dataclass(frozen=True)
class ProtocolParams:
    """Bundles the frozen decisions so a caller can override them as a unit."""

    commit_interarrival_timing: bool = COMMIT_INTERARRIVAL_TIMING
    tunnel_rooting: str = TUNNEL_ROOTING
    recognition_window_epsilon_s: float = RECOGNITION_WINDOW_EPSILON_S
    epoch_length_floor_s: float = EPOCH_LENGTH_FLOOR_S
    epoch_length_cap_s: float = EPOCH_LENGTH_CAP_S
    ratchet_nominal_s: float = RATCHET_NOMINAL_S
    ratchet_jitter_s: float = RATCHET_JITTER_S
    pi_star: float = PI_STAR


DEFAULT_PARAMS = ProtocolParams()
