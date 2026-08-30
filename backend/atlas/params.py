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
#: NOTE: this is the BEACON clock (the public EPOCH key — the aggregator's QRNG
#: epoch — plus the private population Living Key), NOT the device's ratchet clock.
#: The device does not wake on this floor; it consumes the latest cached beacon at
#: its own ratchet tick (see below).
EPOCH_LENGTH_FLOOR_S = 3.0
EPOCH_LENGTH_CAP_S = 30.0


# ---------------------------------------------------------------------------
# Device continuity-ratchet clock (§5.3) — INDEPENDENT of the two beacon clocks
# ---------------------------------------------------------------------------
#
# Three clocks (decoupled):
#   1. Device clock       — local, free-running; drives the continuity ratchet.
#   2. Population LK clock — server SE/HSM-hidden network-wide secret (PRIVATE
#      beacon). Its value is never seen by anyone but the LKG aggregator.
#   3. Public epoch clock — the aggregator's QRNG EPOCH beacon (`beacon.epoch`):
#      the epoch key, fired on aggregate LK-arrival timing, published + signed.
#      External drand is NOT this clock — it is only the bootstrap / defence-in-
#      depth anchor.
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

#: M7 hardening (SECURITY_PRIVACY_REVIEW): clamp each per-sample likelihood into
#: [eps, 1-eps] so no single crafted sample (P(S|¬L)->0) can dominate the posterior;
#: bounds the per-sample likelihood ratio to (1-eps)/eps. Chosen BELOW every legitimate
#: stream's minimum (ambient 0.02, synthetic 0.05) so it is a no-op for real signals.
#: Defensible default — tunable once real-PPG calibration lands (HARDWARE_TESTING.md).
LIVENESS_LIK_CLAMP_EPS = 0.01
#: M7 hardening: minimum samples before the gate may `operate` — a single (or few)
#: crafted sample(s) cannot trip liveness; sustained evidence is required.
LIVENESS_MIN_SAMPLES = 5


# ---------------------------------------------------------------------------
# Cryptographic context separators (§2.3)
# ---------------------------------------------------------------------------

CONTEXT_STORAGE = b"atlas/storage"
CONTEXT_RECOGNITION = b"atlas/recognition"
CONTEXT_TUNNEL = b"atlas/tunnel"

#: ROLE SEPARATION (§2.3). The session key K[t] is a ROOT, not a working key. It
#: previously served three roles verbatim — the value carried forward as the next
#: epoch's `prev_key`, the continuity-ratchet seed, and the recognition ephemeral
#: seed — so `_prev_session_bytes`, `_continuity_key` and the recognition input
#: were three names for one secret. The epoch chain and the continuity chain run
#: on DIFFERENT clocks and are exposed through DIFFERENT surfaces (a
#: `ContinuityTick.continuity_key` is handed to callers as plain bytes); they must
#: not share a seed with each other or with the root. Each role now gets its own
#: one-way HKDF leaf, so compromising one leaf yields neither the root nor the
#: sibling roles.
CONTEXT_CHAIN = b"atlas/chain"            # value fed forward as next epoch's prev_key
CONTEXT_CONTINUITY = b"atlas/continuity"  # seed of the local continuity ratchet

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
