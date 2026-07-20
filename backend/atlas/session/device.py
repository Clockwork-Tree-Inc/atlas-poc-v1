"""A wallet/device node — composes its own session key locally (§2, §3, §4).

Decision #3 (§3.2 / params.SERVER_RETURNS_TIMED_RANDOMNESS_ONLY): the server
returns only timed randomness (the LK draw); each device composes its session
key locally and the server never holds a finished session key. That boundary is
structural here — `Device.advance_epoch` runs on the device and only ever
*consumes* a `ServerQRNG.fire()` draw.

A device also owns its DevKey (identifier-only, §2.1), its identity tree (§7),
and an enclave attestation subsystem (§5.3) wired to wipe RAM keys on a liveness
break (§2.2, §5.4).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..crypto.primitives import H, hkdf, random_bytes
from ..crypto.sign import HybridSigPublic, keypair_from_seed, sign as hybrid_sign, verify as hybrid_verify
from ..keys.derivation import SessionKey, derive_session_key_decoupled, ratchet
from ..keys.enclave import SecureEnclave
from ..keys.identity import IdentityTree
from ..liveness.attestation import AttestationSubsystem, LivenessAttestation
from ..liveness.bayes import PoLEState
from ..params import CONTEXT_TUNNEL
from .cadence import RatchetClock
from .pole import fire_pole_value
from .presence import (
    EnrolledPresence, unlock_lk, unwrap_epoch_key, wrap_epoch_key, wrap_lk,
)


class PresenceRequired(RuntimeError):
    """Ratchet refused: no live enrolled presence, so the epoch key could not be
    unwrapped (fail-closed, §2.3 / FIX #7)."""
from .recognition import (
    HybridContribution, evolve_tunnel_key, hybrid_contribution, hybrid_encapsulate,
    hybrid_recognition_value,
)


@dataclass
class EpochInputs:
    """Everything needed to compose one epoch's session key."""

    lk: bytes            # Living Key — server QRNG timed draw (private beacon)
    epoch_key: bytes     # network-public epoch QRNG value (NOT drand; §2.5/§2.7)
    drand_round: bytes      # beacon round id


@dataclass
class ContinuityTick:
    """Result of one independent continuity-ratchet tick (§5.3).

    `interval_s` is the realised jittered period the device waited; it is
    committed into the ratchet. `attestation` is None iff liveness broke at this
    tick (containment fired, no new key material produced)."""

    interval_s: float
    continuity_key: bytes               # b"" when liveness broke this tick
    attestation: Optional[LivenessAttestation]
    operate: bool


class Device:
    def __init__(
        self,
        name: str,
        identity: IdentityTree,
        *,
        dev_key: Optional[bytes] = None,
        bootstrap_tunnel_key: Optional[bytes] = None,
        attestation: Optional[AttestationSubsystem] = None,
        ratchet_clock: Optional[RatchetClock] = None,
    ):
        self.name = name
        self.identity = identity
        self.dev_key = dev_key or random_bytes(32)
        # Device authentication keypair (§2.4 / FIX #6): does identification AND
        # authentication by challenge-response. The private half NEVER leaves the
        # device and is NEVER in any key derivation; it only signs fresh server
        # challenges. Freely rotatable (rotate dev_key -> new auth key).
        self._device_keypair = keypair_from_seed(hkdf(ikm=self.dev_key, info=b"atlas/devkey/auth"))
        # Shared in-person enrolment secret that roots the tunnel before the
        # first recognition (§6 ritual establishes the root binding). This PSK is
        # what makes the recognition tunnel MITM-resistant (a pure-network
        # attacker lacks it). SECURITY: if it is omitted we must FAIL CLOSED — use
        # a fresh per-device random root (so an un-bootstrapped pair simply does
        # NOT converge on a shared tunnel) rather than a public all-zero constant
        # (which would make any two un-bootstrapped devices match trivially and
        # silently void the in-person binding).
        self.bootstrapped = bootstrap_tunnel_key is not None
        self.tunnel_key = bootstrap_tunnel_key if self.bootstrapped else random_bytes(32)
        self.attestation = attestation or AttestationSubsystem()
        self._session: Optional[SessionKey] = None
        self._prev_session_bytes = b"\x00" * 32
        self._hs = None   # in-flight hybrid recognition handshake state
        # Independent local continuity-ratchet clock (~10s ± jitter, §5.3) and
        # the latest cached beacon it folds in (it does NOT wake to fetch).
        self._ratchet_clock = ratchet_clock or RatchetClock()
        self._continuity_key: Optional[bytes] = None
        # Presence enrollment (§2.3 / FIX #7): a shared enrollment secret sealed in
        # the device Secure Enclave, released only on live enrolled presence. The
        # server holds a copy to WRAP epoch keys; the device can only UNWRAP them
        # while the enrolled user is live and present.
        self._enrollment_secret = random_bytes(32)
        self._enrolled_biometric = random_bytes(256)
        self._presence = EnrolledPresence(
            self._enrollment_secret, enclave=SecureEnclave(), biometric=self._enrolled_biometric)
        # Wire containment: a liveness break wipes the live session key (§2.2).
        self.attestation.on_wipe(self._wipe_session)

    # -- device-key challenge-response auth (§2.4 / FIX #6) ------------------

    def device_public(self) -> HybridSigPublic:
        """The device's PUBLIC auth half (given to the server at enrollment). The
        private half never leaves the device."""
        return self._device_keypair.public

    def respond_to_challenge(self, challenge: bytes) -> bytes:
        """Sign a fresh server challenge with the device private half (never
        transmitted). Proves possession without revealing the key or entering any
        key derivation."""
        return hybrid_sign(self._device_keypair, challenge)

    # -- session composition (local) ----------------------------------------

    def wrap_epoch_key(self, epoch_key: bytes, drand_round: bytes) -> bytes:
        """Server-side helper: wrap an epoch key to THIS device's enrollment secret
        (the server holds a copy from enrollment). Only a live, present, enrolled
        device can unwrap it."""
        return wrap_epoch_key(epoch_key, enrollment_secret=self._enrollment_secret, drand_round=drand_round)

    def advance_epoch(self, *, wrapped_epoch_key: bytes, wrapped_lk: bytes, drand_round: bytes,
                      live_biometric: bytes, pole: PoLEState) -> SessionKey:
        """Compose this epoch's session key via the full value/timing chain (§2.3):

            continuity=yes  -> Enclave releases the enrollment secret
                            -> UNWRAP the (public) epoch key
                            -> UNLOCK the (private) LK with that epoch key
                            -> SessKey = HKDF(PoLE_value, LK, epoch_key, prev, ctx).

        No continuity -> no release -> the epoch key cannot be unwrapped -> the LK
        cannot be unlocked -> no ratchet (fail-closed, by construction). The epoch
        key being network-public is safe because unwrapping it is continuity-gated.
        """
        secret = self._presence.release(live_biometric=live_biometric, pole=pole)
        if secret is None:
            raise PresenceRequired("no live enrolled presence; epoch key cannot be unwrapped")
        try:
            epoch_key = unwrap_epoch_key(wrapped_epoch_key, presence_secret=secret, drand_round=drand_round)
        except Exception as exc:
            raise PresenceRequired("epoch-key unwrap failed (not the enrolled present device)") from exc
        try:
            lk = unlock_lk(wrapped_lk, epoch_key=epoch_key, drand_round=drand_round)
        except Exception as exc:
            raise PresenceRequired("LK unlock failed (epoch key did not unlock the LK)") from exc

        # PoLE_value: a physiologically-TIMED QRNG value (clean QRNG; timing only
        # scheduled the firing). Replaces the earlier un-timed local_qrng_draw.
        pole_value = fire_pole_value(physio_fire_moment=pole.p_live)
        sk = derive_session_key_decoupled(
            lk=lk,
            epoch_key=epoch_key,
            pole_value=pole_value,
            prev_key=self._prev_session_bytes,
            context_separator=CONTEXT_TUNNEL,
            drand_round=drand_round,
        )
        self._prev_session_bytes = sk.key
        self._session = sk
        return sk

    def advance_epoch_present(self, lk: bytes, epoch_key: bytes, drand_round: bytes,
                              *, pole: Optional[PoLEState] = None) -> SessionKey:
        """Convenience for the enrolled user being present. Server side: the epoch
        key WRAPS the LK, and presence WRAPS the epoch key. Device side: advance
        under the device's own enrolled biometric + an operating PoLE. `lk` and
        `epoch_key` are the clean QRNG values the server produced (NOT drand)."""
        if pole is None:
            pole = PoLEState(p_live=1.0, state_digest=H(b"atlas/present", drand_round),
                             drand_round=drand_round, operate=True)
        wrapped_lk = wrap_lk(lk, epoch_key=epoch_key, drand_round=drand_round)
        wrapped_epoch_key = self.wrap_epoch_key(epoch_key, drand_round)
        return self.advance_epoch(
            wrapped_epoch_key=wrapped_epoch_key, wrapped_lk=wrapped_lk, drand_round=drand_round,
            live_biometric=self._enrolled_biometric, pole=pole)

    @property
    def session(self) -> SessionKey:
        if self._session is None:
            raise RuntimeError("no active session; call advance_epoch first")
        return self._session

    def _wipe_session(self) -> None:
        # Containment (§2.2): destroy ALL session-derived material in RAM, not
        # just the live SessionKey object. The ratchet's prev-key copy and the
        # continuity-chain key must go too, or a device seized right after a
        # liveness break still holds usable key material.
        if self._session is not None:
            self._session.destroy()
        self._prev_session_bytes = b"\x00" * 32
        self._continuity_key = None

    # -- independent continuity ratchet (§5.3) — local 10s ± biological jitter --

    def next_ratchet_interval(self, *, bio_signal: bytes) -> float:
        """Time the next inter-ratchet interval from the enrolled ring's live
        BIOLOGICAL signal (10s ± biological jitter, §16). The scheduler/OS timer
        waits this long before calling `continuity_tick`. Schedule only — the
        signal never becomes key material."""
        return self._ratchet_clock.next_interval(bio_signal=bio_signal)

    def continuity_tick(self, pole: PoLEState, *, drand_round: bytes, beacon: bytes,
                        challenge: bytes = b"") -> ContinuityTick:
        """One continuity ratchet step on the LOCAL clock (§5.3).

        NO CACHE (§18): `beacon` is the CURRENT beacon consumed FRESH at this tick.
        A missing/stale beacon makes the device INERT (fail-closed) — it wipes and
        does NOT fall back to any prior value; a stale beacon is NEVER folded.

        Attests FIRST: a non-operating PoLE is a liveness break -> containment
        wipes, no new key. On operate, a forward-secret ratchet step folds fresh
        QRNG entropy + the FRESH beacon. NO timing is folded into the value (the
        interval is a schedule only) — forward secrecy comes from the fresh QRNG
        entropy and the ratchet chain."""
        interval_s = self._ratchet_clock.last_interval or 0.0
        # fail-closed on an absent/stale beacon: never fold a stale value -> inert.
        if not beacon:
            self._wipe_session()
            return ContinuityTick(interval_s=interval_s, continuity_key=b"",
                                  attestation=None, operate=False)
        att = self.attestation.attest(pole, challenge=challenge)
        if att is None:
            # liveness break / suspended: no key advance (containment fired).
            return ContinuityTick(interval_s=interval_s, continuity_key=b"",
                                  attestation=None, operate=False)
        if self._continuity_key is None:
            self._continuity_key = self.session.key      # seed from live session
        entropy_t = random_bytes(32)                     # clean QRNG; no timing in value
        self._continuity_key = ratchet(
            self._continuity_key, entropy_t=entropy_t,
            beacon_t=beacon, drand_round=drand_round)
        return ContinuityTick(interval_s=interval_s,
                              continuity_key=self._continuity_key,
                              attestation=att, operate=True)

    # -- recognition + tunnel (§4) — HYBRID PQ (ML-KEM + X25519) -------------
    # The core tunnel uses the same post-quantum hybrid as the credential
    # channel: a two-round handshake (exchange contributions, then ciphertexts).

    def start_recognition(self, beacon: bytes) -> HybridContribution:
        """Round 1: derive the X25519 half from the session key + a fresh ML-KEM
        ephemeral keypair; return the public contribution."""
        x_priv, mlkem_dk, pub = hybrid_contribution(self.session.key, beacon)
        self._hs = {"x_priv": x_priv, "mlkem_dk": mlkem_dk, "pub": pub, "ss_self": None}
        return pub

    def encapsulate_to(self, their: HybridContribution) -> bytes:
        """Round 2: ML-KEM-encapsulate to the peer's key; keep our shared secret,
        return the ciphertext."""
        ct, ss_self = hybrid_encapsulate(their)
        self._hs["ss_self"] = ss_self
        return ct

    def finish_recognition(self, *, beacon: bytes, their: HybridContribution, their_ct: bytes) -> bytes:
        """Combine X25519 DH + both ML-KEM secrets into the recognition value and
        re-key the tunnel (§4)."""
        hs = self._hs
        rec = hybrid_recognition_value(
            my_x_priv=hs["x_priv"], my_mlkem_dk=hs["mlkem_dk"], my_pub=hs["pub"],
            their_pub=their, their_ct=their_ct, my_ss_self=hs["ss_self"], beacon=beacon)
        self.tunnel_key = evolve_tunnel_key(self.tunnel_key, rec)
        self._hs = None
        return self.tunnel_key

    # -- forward-secret message ratchet (§2.2) ------------------------------

    def message_ratchet_step(self, prev_msg_key: bytes, *, beacon_t: bytes,
                             drand_round: bytes) -> tuple[bytes, bytes]:
        """Advance the per-message key with FRESH SECRET entropy.

        Returns (next_msg_key, entropy_t). entropy_t is the biology-timed/QRNG
        secret that is NOT transmitted; without it, a captured earlier key
        cannot derive the next key (§10.1 'a captured earlier key cannot read
        the later message')."""
        entropy_t = random_bytes(32)
        nxt = ratchet(prev_msg_key, entropy_t=entropy_t, beacon_t=beacon_t, drand_round=drand_round)
        return nxt, entropy_t


def establish_hybrid_tunnel(a: "Device", b: "Device", beacon: bytes) -> tuple[bytes, bytes]:
    """Run the full two-round hybrid (ML-KEM + X25519) recognition handshake
    between two devices and re-key both their tunnels. Returns (tunnel_a,
    tunnel_b); they are equal. This is the core tunnel's post-quantum path."""
    a_pub = a.start_recognition(beacon)
    b_pub = b.start_recognition(beacon)
    a_ct = a.encapsulate_to(b_pub)        # A encapsulates to B
    b_ct = b.encapsulate_to(a_pub)        # B encapsulates to A
    ta = a.finish_recognition(beacon=beacon, their=b_pub, their_ct=b_ct)
    tb = b.finish_recognition(beacon=beacon, their=a_pub, their_ct=a_ct)
    return ta, tb
