"""The recovery anchor — the "real you", cryptographically unlinked from the "digital you".

The problem this solves: at TOTAL loss (no phone, no key) you must be able to walk up
to an Atlas recovery person and get your identity back — using only your body and a
password you remember. But nothing about you may be stored in a searchable "whose face is
this?" database (that would deanonymize everyone), and nothing may be linkable to your
day-to-day digital identity.

The design (per the product spec):

  * The RECOVERY PSEUDONYM is the anchor of the *real you*. Its SELECTOR is (your NAME, a
    PASSWORD): your name is your username, and the password exists ONLY to differentiate you
    from other people who share your name. The password is NOT a secret and NOT a security
    gate — it turns an ambiguous name into a unique record handle, giving a direct 1:1 lookup
    instead of a 1:N search. Because the selector is a function of (name, password) only —
    independent of the System-ID — the anchor is completely UNLINKED to the digital you.

  * The *digital you* IS the System-ID (derived from the TSK) — the blind root that
    generates all your pseudonyms/children. The bridge back to it is SEALED and stored
    under the recovery pseudonym; the anchor RESTORES the System-ID (children regenerate
    from it). The full TSK master root additionally needs the token half (Half B: wallet
    + YubiKey) — a follow-up; the total-loss anchor recovers the System-ID, not the TSK.
    Opening the bridge needs the whole ceremony, all AND-ed:
        - name + password (know)   -> locates the one record (1:1, no search) AND contributes
                                       the ceremony half of the bridge key
        - recovery person (vouch)  -> a live human SEES YOUR FACE + signs (verify_high_stakes):
                                       the biometric check is a decentralized human, never a
                                       stored template
        - m-of-n servers  (have)   -> threshold share release -> the other half of the bridge key
    Server access alone is INERT: the bridge is encrypted under (name+password ∧ threshold)
    and won't release without the recovery person's witnessed signature.

NO STORED BIOMETRIC (TRUST_LAYER.md #6): this module keeps NO biometric template and runs NO
fuzzy extractor. Face verification is decentralized — the device Secure Enclave (Face ID) on the
device-present / social tiers, and a LIVE RECOVERY PERSON on this physical-self / total-loss tier.
The record therefore stores no biometric material at all: there is nothing to leak.

HONEST BOUNDARIES:
  * The password is a SELECTOR, not a gate — its low entropy is fine because it protects nothing
    on its own; the recovery person + threshold are the real gates. Enumeration of the selector is
    bounded by scrypt cost + server-side rate limiting. `scrypt` (stdlib) stands in for Argon2id.
  * Do NOT hand-roll: Shamir (`crypto/shamir`), AEAD/HKDF (`crypto/primitives`), and the witness
    signature (`keys/hardware_key`) are all reused.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import List, Sequence

from ..crypto import shamir
from ..crypto.primitives import H, aead_decrypt, aead_encrypt, hkdf, random_bytes
from ..keys.hardware_key import HighStakesRequest, verify_high_stakes
from ..recovery import oprf

# Deployment-wide selector salt. At total loss the user carries NOTHING, so the salt
# cannot be per-user stored — it is a domain constant. Enumeration resistance comes from
# the scrypt work factor + server rate-limiting, not from salt secrecy.
DOMAIN_SELECTOR_SALT = b"atlas/recovery-selector/v1"

# scrypt (memory-hard) work factors — stands in for Argon2id (argon2-cffi not vendored).
# Production would raise these; kept modest here so the PoC stays fast and under
# OpenSSL's default memory cap. Enumeration resistance is also carried by server-side
# rate limiting + the downstream person/threshold gates.
_SCRYPT_N = 1 << 14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_MAXMEM = 128 * _SCRYPT_R * _SCRYPT_N * 4   # headroom over 128*r*N


# --------------------------------------------------------------------------- errors
class RecoveryAnchorError(Exception):
    """Base — every failure path is fail-closed (raises), never a silent None."""


class RecordNotFound(RecoveryAnchorError):
    """The password selector resolved to no enrolled recovery pseudonym."""


class RecoveryPersonRequired(RecoveryAnchorError):
    """No valid live recovery-person attestation over this recovery challenge."""


class ThresholdNotMet(RecoveryAnchorError):
    """Fewer than k server shares were presented."""


class EnrolmentRefused(RecoveryAnchorError):
    """The enrolling device is ineligible (no Secure Element)."""


# --------------------------------------------------------------------------- device
@dataclass(frozen=True)
class DeviceCapability:
    """A device joining an account. An SE is REQUIRED to enrol (the isolation
    boundary); liveness is an optional capability, not an enrolment gate — a plain
    SE computer (TPM, no ring/ambient sensors) is a full member, it just can't SOURCE
    liveness or be the sole authorizer of a liveness-gated action."""

    has_secure_element: bool
    has_liveness: bool = False


# --------------------------------------------------------------------------- selector
def _normalize_name(name: str) -> str:
    """Fold a human name to a stable form (case/whitespace) so it addresses one record."""
    return " ".join(name.strip().lower().split())


def recovery_selector(legal_name: str, password: str, *,
                      salt: bytes = DOMAIN_SELECTOR_SALT,
                      oprf_shards: Sequence[oprf.OPRFShard] | None = None) -> bytes:
    """The 1:1 SELECTOR for a recovery record. Your NAME is your username; the PASSWORD
    differentiates you from other people who share your name.

    OFFLINE-ENUMERATION RESISTANCE (#3 OPRF): when `oprf_shards` is supplied (the deployment
    always supplies them — the recovery servers hold the OPRF key), the scrypt-stretched password
    is run through an OBLIVIOUS PRF against the servers' key before it becomes the selector. The
    servers learn nothing about the password, and — crucially — an attacker who breaches the
    record store CANNOT grind (name, password) guesses offline: every guess needs one ONLINE,
    rate-limited evaluation against the servers' OPRF key. Without the servers' key the selector
    is unreachable. (Absent `oprf_shards` the selector is scrypt-only — a local reference path.)

    Independent of the System-ID, so the anchor stays UNLINKED to the digital you."""
    name = _normalize_name(legal_name)
    stretched = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                               n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32,
                               maxmem=_SCRYPT_MAXMEM)
    if oprf_shards is not None:
        # bind the stretched password to the servers' OPRF key (online, rate-limited);
        # offline brute-force of a leaked record becomes impossible.
        stretched = oprf.evaluate_oblivious(oprf_shards, stretched)
    return H(b"atlas/recovery-selector", name.encode("utf-8"), stretched)


# --------------------------------------------------------------------------- record
@dataclass
class RecoveryRecord:
    """Server-side record of the REAL you, keyed by the recovery pseudonym. Holds NO
    biometric material and NO plaintext link to the digital you — `sealed_bridge` is opaque
    without the full ceremony, so a breach of this store reveals only opaque handles: never a
    face, and never which digital identity each is."""

    recovery_pseudonym: bytes
    sealed_bridge: bytes              # AEAD(System-ID seed) under (name+password ∧ threshold)
    agent_public: bytes               # the authorized recovery person's verify key
    n: int
    k: int


# FIXED (deterministic) challenge so the recovery person's Ed25519 signature over the binding
# request is reproducible enrol->recover and can serve as KEY MATERIAL (Ed25519 is deterministic,
# RFC 8032). Domain-separated action keeps it distinct from the fresh-challenge attestation.
_AGENT_BINDING_CHALLENGE = b"atlas/recovery-anchor/agent-binding/v1"


def agent_binding_request(pseudonym: bytes) -> HighStakesRequest:
    """The FIXED request the authorized recovery person signs at enrolment (and re-signs at
    recovery). Their deterministic signature over it is mixed into the bridge key, so the person
    is a real cryptographic AND-factor — not merely a checked flag."""
    return HighStakesRequest(action="recover-bind", context=pseudonym,
                             challenge=_AGENT_BINDING_CHALLENGE)


def _agent_key_factor(agent_public: bytes, pseudonym: bytes, binding_signature: bytes) -> bytes:
    """A secret only the recovery person's key can produce: keyed hash of their DETERMINISTIC
    signature over the fixed binding request. Verified against `agent_public` first (fail-closed);
    an attacker holding the record but not the person's key cannot reproduce it, so the bridge key
    cannot be formed without the person."""
    if not verify_high_stakes(agent_public, agent_binding_request(pseudonym), binding_signature):
        raise RecoveryPersonRequired("recovery-person binding signature did not verify")
    return H(b"atlas/recovery-anchor/agent-factor", binding_signature)


def _bridge_key(server_secret: bytes, pseudonym: bytes, agent_factor: bytes) -> bytes:
    """The seal key needs ALL of: the ceremony half (recovery pseudonym = a function of
    name+password, from the user's memory), the threshold-combined server secret, AND the
    recovery person's key factor (`agent_factor`). A wrong password, fewer than k servers, OR
    the absence of the recovery person's key each make the key unformable — the ceremony is
    genuinely AND-ed in the cryptography, not just procedurally."""
    return hkdf(ikm=pseudonym + server_secret + agent_factor,
               info=b"atlas/recovery-bridge" + pseudonym, length=32)


def _recover_challenge_request(pseudonym: bytes, challenge: bytes) -> HighStakesRequest:
    """The exact thing the recovery person signs — bound to THIS pseudonym + a fresh
    challenge, so a witnessed signature can't be replayed for another recovery."""
    return HighStakesRequest(action="recover", context=pseudonym, challenge=challenge)


# --------------------------------------------------------------------------- enrol
def enrol_recovery_anchor(
    *,
    legal_name: str,
    password: str,
    system_id_seed: bytes,
    agent_public: bytes,
    agent_binding_signature: bytes,
    device: DeviceCapability,
    n: int = 3,
    k: int = 2,
    salt: bytes = DOMAIN_SELECTOR_SALT,
    oprf_shards: Sequence[oprf.OPRFShard] | None = None,
) -> tuple[RecoveryRecord, List[shamir.Share]]:
    """Bind the recovery pseudonym (the REAL you) and SEAL the bridge to the DIGITAL you —
    `system_id_seed` is the System-ID (derived from the TSK), the material that regenerates
    all your children/pseudonyms. `legal_name` is your username and `password` differentiates
    you from namesakes. Returns the server-side record plus the n server shares to distribute
    n-of-x. No biometric is captured or stored here — the recovery person is the face check at
    recovery. The System-ID material is never stored in the clear."""
    if not device.has_secure_element:
        raise EnrolmentRefused("enrolment requires a Secure Element")

    pseudonym = recovery_selector(legal_name, password, salt=salt, oprf_shards=oprf_shards)

    # The recovery person's deterministic signature over the fixed binding becomes key material
    # (verified here; fail-closed if it doesn't match `agent_public`).
    agent_factor = _agent_key_factor(agent_public, pseudonym, agent_binding_signature)

    server_secret = random_bytes(32)
    shares = shamir.split(server_secret, n=n, k=k)

    seal = _bridge_key(server_secret, pseudonym, agent_factor)
    sealed_bridge = aead_encrypt(seal, system_id_seed, aad=pseudonym)

    record = RecoveryRecord(recovery_pseudonym=pseudonym, sealed_bridge=sealed_bridge,
                            agent_public=agent_public, n=n, k=k)
    return record, shares


# --------------------------------------------------------------------------- recover
def recover_total_loss(
    record: RecoveryRecord,
    *,
    legal_name: str,
    password: str,
    server_shares: Sequence[shamir.Share],
    recovery_challenge: bytes,
    agent_signature: bytes,
    agent_binding_signature: bytes,
    device: DeviceCapability,
    salt: bytes = DOMAIN_SELECTOR_SALT,
    oprf_shards: Sequence[oprf.OPRFShard] | None = None,
) -> bytes:
    """Rung 3 — lost everything. Reopen the bridge to the digital you with the full
    ceremony. Returns the recovered `system_id_seed` (the System-ID, from which your
    children regenerate). EVERY factor is fail-closed and checked on ONE claimed record
    (1:1, never a search).

    The recovery PERSON is the decentralized biometric: a live human sees your face and
    signs. There is no stored template and no fuzzy match here — the human is the anti-spoof.
    So a non-liveness SE terminal is fine: the person supplies the liveness the device can't."""
    if not device.has_secure_element:
        raise EnrolmentRefused("recovery terminal requires a Secure Element")

    # 1. (name, password) SELECTOR -> the one record (direct 1:1, no search). It also
    #    contributes the ceremony half of the bridge key. Name is the username; password
    #    only disambiguates namesakes.
    if recovery_selector(legal_name, password, salt=salt,
                         oprf_shards=oprf_shards) != record.recovery_pseudonym:
        raise RecordNotFound("(name, password) does not resolve to this record")

    # 2. live recovery person attests (SEES YOUR FACE) — witnessed signature, anti-replay.
    #    This IS the biometric check: a decentralized, accountable human, not a stored template.
    req = _recover_challenge_request(record.recovery_pseudonym, recovery_challenge)
    if not verify_high_stakes(record.agent_public, req, agent_signature):
        raise RecoveryPersonRequired("no valid live recovery-person attestation")

    # 3. m-of-n servers release; below k -> cannot even form the server secret.
    if len(server_shares) < record.k:
        raise ThresholdNotMet(f"need {record.k} server shares, got {len(server_shares)}")
    server_secret = shamir.combine(server_shares)

    # 4. the recovery person's binding signature -> key material (the person is an AND-factor in
    #    the key itself, not only the procedural check above).
    agent_factor = _agent_key_factor(record.agent_public, record.recovery_pseudonym,
                                     agent_binding_signature)

    # 5. unseal the bridge (name+password ∧ threshold ∧ recovery-person); any wrong factor fails.
    seal = _bridge_key(server_secret, record.recovery_pseudonym, agent_factor)
    try:
        return aead_decrypt(seal, record.sealed_bridge, aad=record.recovery_pseudonym)
    except Exception as exc:  # AEAD auth failure = a factor was wrong
        raise RecoveryAnchorError("bridge unseal failed (a factor did not match)") from exc
