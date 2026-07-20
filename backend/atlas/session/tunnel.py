"""The two send modes and the shared encryption core (§9).

Both modes use the same AES-256-GCM core and are content-type-agnostic (§9 —
text, photo, audio, video, file). Text and photo are the two built demos.

  Mode 1 (§9.1) — normal encrypted content. Standard E2E under the tunnel/
    recipient key; recipient decrypts and views. No liveness gate on viewing.

  Mode 2 (§9.2) — verified-human-only content. Same encryption, but unwrapping
    the content key requires, at view time:
      (1) a current network-supplied beacon/epoch component,
      (2) the recipient's current liveness attestation, signed by the key the
          sender pinned (H(enclave_public)), and
      (3) that attestation answering a FRESH challenge picked at open time
          (so a captured attestation cannot be replayed within the epoch).
    A stolen device, bot, script, or offline non-present holder cannot view it.
    Yields revocation (withhold the component), epoch-expiry, access logging.

Honest boundary (§9.2) — what the SOFTWARE here proves vs what is hardware-gated:
  * Proven in code: the content key is cryptographically bound to the beacon
    component and the pinned enclave public key, and is releasable only by a
    party that can produce a FRESH, valid signature over our challenge — i.e.
    "the holder of that key, live and online now." The gate holds up to the
    first authorized view; a legitimate verified viewer can still screenshot —
    the claim is "viewing requires being online and verified-live; access is
    revocable and logged," not DRM.
  * Hardware-gated (NOT proven here): that the signing key genuinely lives in a
    non-extractable, biometry-gated Secure Enclave (vs an extracted software
    key). That root-of-trust is Apple App Attest / DeviceCheck; until it runs on
    device (HARDWARE_TESTING.md), "unwrapped inside their Secure Enclave" is the
    intended deployment, not a property this model establishes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, List, Optional

from ..crypto.primitives import H, aead_decrypt, aead_encrypt, hkdf_combine, random_bytes
from typing import Union
from ..liveness.attestation import LivenessAttestation


class SendMode(Enum):
    NORMAL = 1            # §9.1
    VERIFIED_HUMAN = 2    # §9.2


class AccessDenied(RuntimeError):
    pass


@dataclass
class Message:
    mode: SendMode
    ciphertext: bytes                      # content under content_key (nonce+ct)
    # Mode-2 gating fields (empty for Mode 1):
    wrapped_content_key: bytes = b""
    required_beacon_component: bytes = b""  # the epoch component bound at seal
    enclave_requirement: bytes = b""        # H(recipient enclave public)
    access_log: List[str] = field(default_factory=list)


def _content_key_mode1(key: bytes) -> bytes:
    return hkdf_combine([key], info=b"atlas/mode1/content", length=32)


def _gate_key(key: bytes, beacon_component: bytes, enclave_requirement: bytes) -> bytes:
    return hkdf_combine(
        [key, beacon_component, enclave_requirement], info=b"atlas/mode2/gate", length=32
    )


def seal(
    plaintext: bytes,
    *,
    mode: SendMode,
    key: bytes,
    aad: bytes = b"",
    beacon_component: Optional[bytes] = None,
    recipient_enclave_public=None,
) -> Message:
    if mode == SendMode.NORMAL:
        ck = _content_key_mode1(key)
        return Message(mode=mode, ciphertext=aead_encrypt(ck, plaintext, aad))

    # Mode 2: random content key, gated wrapping.
    if beacon_component is None or recipient_enclave_public is None:
        raise ValueError("Mode 2 requires beacon_component and recipient_enclave_public")
    ck = random_bytes(32)
    ciphertext = aead_encrypt(ck, plaintext, aad)
    enclave_req = H(b"atlas/enclave-req", recipient_enclave_public.encode())
    gate = _gate_key(key, beacon_component, enclave_req)
    wrapped = aead_encrypt(gate, ck, aad=b"atlas/mode2/wrap")
    return Message(
        mode=mode,
        ciphertext=ciphertext,
        wrapped_content_key=wrapped,
        required_beacon_component=beacon_component,
        enclave_requirement=enclave_req,
    )


# A liveness provider is given the relying-party's fresh challenge nonce and must
# return an attestation signed over it (a live Enclave can; a replay holder
# cannot). Zero-arg providers are still accepted for backward compatibility, but
# they cannot satisfy the freshness check and so are denied.
AttestationProvider = Union[
    Callable[[bytes], Optional[LivenessAttestation]],
    Callable[[], Optional[LivenessAttestation]],
]


def _call_provider(provider: AttestationProvider, challenge: bytes):
    try:
        return provider(challenge)            # freshness-aware provider
    except TypeError:
        return provider()                     # legacy zero-arg provider


def open_message(
    msg: Message,
    *,
    key: bytes,
    aad: bytes = b"",
    current_beacon_component: Optional[bytes] = None,
    attestation_provider: Optional[AttestationProvider] = None,
    expected_drand_round: Optional[bytes] = None,
) -> bytes:
    """Open a message. Mode 2 enforces the live-human gate (§9.2)."""
    if msg.mode == SendMode.NORMAL:
        ck = _content_key_mode1(key)
        return aead_decrypt(ck, msg.ciphertext, aad)

    # Mode 2 gate.
    # (1) must be online: a current network-supplied beacon component, and it
    #     must still match the bound epoch (else epoch-expiry / revocation).
    if current_beacon_component is None:
        msg.access_log.append("denied: offline (no current beacon component)")
        raise AccessDenied("offline: no current beacon/epoch component")
    if current_beacon_component != msg.required_beacon_component:
        msg.access_log.append("denied: epoch expired / component revoked")
        raise AccessDenied("epoch expired or component revoked")

    # (2) must be verified-live: a fresh, valid enclave liveness attestation,
    #     signed over a challenge we pick now (anti-replay within an epoch).
    challenge = random_bytes(16)
    att = _call_provider(attestation_provider, challenge) if attestation_provider else None
    if att is None or not att.verify() or not att.operate:
        msg.access_log.append("denied: no current liveness attestation")
        raise AccessDenied("recipient not verified-live (no current attestation)")
    if att.challenge != challenge:
        msg.access_log.append("denied: stale/replayed attestation (challenge mismatch)")
        raise AccessDenied("attestation does not answer this view's freshness challenge")
    if expected_drand_round is not None and att.drand_round != expected_drand_round:
        msg.access_log.append("denied: attestation epoch mismatch")
        raise AccessDenied("attestation is not for the current epoch")
    if H(b"atlas/enclave-req", att.enclave_public.encode()) != msg.enclave_requirement:
        msg.access_log.append("denied: attestation from wrong enclave")
        raise AccessDenied("attestation enclave does not match recipient")

    gate = _gate_key(key, current_beacon_component, msg.enclave_requirement)
    try:
        ck = aead_decrypt(gate, msg.wrapped_content_key, aad=b"atlas/mode2/wrap")
    except Exception as exc:  # pragma: no cover - defensive
        msg.access_log.append("denied: gate unwrap failed")
        raise AccessDenied("gate unwrap failed") from exc
    plaintext = aead_decrypt(ck, msg.ciphertext, aad)
    msg.access_log.append("granted: verified-live, on-network")
    return plaintext  # non-persistent: caller must not store (re-verify each view)
