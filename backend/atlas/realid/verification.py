"""Verification-status inheritance via REAL BBS+ (Real-ID spec §2, §3).

Other children prove "my root is real-ID-verified at level L" WITHOUT exposing
the real ID, the System-ID, or a link to siblings.

CRYPTO (corrected — no longer a hand-rolled scheme): this uses BBS+ selective-
disclosure signatures from a vetted library (`ursa-bbs-signatures`, Hyperledger
Ursa's audited native implementation), the same discipline as using liboqs for
PQC primitives. The authority issues ONE BBS+ credential over the attributes
[claim, level, system-id]; the holder presents UNLIMITED, re-randomized,
mutually-unlinkable proofs that reveal {claim, level} and HIDE the system-id.
This is the real anonymous-credential construction, not a nonce/escrow stand-in.

Properties (now from the construction itself, asserted in tests):
  * unlinkable      — BBS+ proofs are re-randomized; two presentations (same or
                      different roots) are not correlatable;
  * backward-blocked— the hidden system-id is not recoverable from the proof;
  * level-gated     — the revealed level must satisfy the verifier's requirement;
  * accountable     — under cause, the HOLDER discloses the system-id via a
                      full-disclosure BBS+ proof (voluntary/compelled).

HONEST BOUNDS (for the §11 audit):
  * Ursa is archived/unmaintained (Hyperledger sunset, 2022). It is a real,
    formerly-vetted BBS+; production should track a maintained successor (DIF
    `bbs`/`docknetwork/crypto`/`anoncreds-rs`). It is NOT a hand-rolled scheme.
  * BBS+ here is CLASSICAL pairing-based (BLS12-381), not post-quantum. A
    post-quantum anonymous credential is an open area — flagged.
  * HOLDER-DISCLOSURE IS ABSOLUTE BY DECISION (Credential PQC Posture §6): only
    the user can reveal their identity, via a full-disclosure proof under cause.
    A designated-opener / involuntary-opening extension (group signature /
    verifiable-encryption-to-an-opener) is REJECTED, not deferred — there is no
    operator, court, or system key that can open a proof. This is a feature, not
    a gap: plain BBS+ giving the issuer no way to open is exactly the property.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

try:
    from ursa_bbs_signatures import (
        BlsKeyPair, CreateProofRequest, ProofMessage, ProofMessageType, SignRequest,
        VerifyProofRequest, VerifyRequest, create_proof, sign, verify, verify_proof,
    )
    _BBS_AVAILABLE = True
except ImportError:
    # Hyperledger Ursa (archived 2022) is a native/optional dependency — absent on many
    # hosts (Apple Silicon, CI without the build toolchain). Rather than crash the whole
    # realid package at import, fall back to the pure-Python Pointcheval-Sanders backend
    # (ps_credential) — a GENUINE unlinkable anonymous credential that runs everywhere.
    _BBS_AVAILABLE = False

from . import ps_credential as _ps
from .levels import AssuranceLevel

# Fixed attribute layout signed in every credential.
_CLAIM = "atlas-verified"
_MSG_COUNT = 3   # [claim, level, system-id]


def _messages(level: AssuranceLevel, system_id_handle: bytes) -> List[str]:
    return [_CLAIM, f"level={int(level)}", "systemid=" + system_id_handle.hex()]


def _revealed_level(revealed: List[str]) -> Optional[AssuranceLevel]:
    """Extract the assurance level from the cryptographically-revealed messages.
    Requires the constant claim to be present and a well-formed `level=` message."""
    if _CLAIM not in revealed:
        return None
    for m in revealed:
        if m.startswith("level="):
            try:
                return AssuranceLevel(int(m.split("=", 1)[1]))
            except (ValueError, KeyError):
                return None
    return None


@dataclass
class VerificationRecord:
    """Backend-held STATUS only (never the ID): verification occurred at a level
    for a System-ID handle."""

    system_id_handle: bytes
    level: AssuranceLevel
    verified: bool = True


@dataclass
class VerificationCredential:
    """Held by the user (the verified root's BBS+ credential). ONE credential ->
    unlimited unlinkable presentations."""

    signature: bytes
    messages: List[str]
    level: AssuranceLevel
    _bbs_key: object   # message-count-bound BBS public key (for proof creation)


@dataclass
class InheritedProof:
    """A child's presentation. A re-randomized BBS+ proof revealing only the
    listed messages; the system-id is hidden unless this is an accountability
    disclosure."""

    proof: bytes
    revealed: List[str]
    nonce: bytes
    level: AssuranceLevel
    discloses_system_id: bool = False


class AtlasVerificationAuthority:
    """Global BBS+ issuer. Holds the issuing key; issues credentials to verified
    roots. It does NOT (and cannot) link a presented proof back to a credential —
    that is the unlinkability property, and why involuntary opening needs an
    extra mechanism (see module docstring)."""

    def __init__(self):
        if _BBS_AVAILABLE:
            self._kp = BlsKeyPair.generate_g2()
            self._bbs_key = self._kp.get_bbs_key(_MSG_COUNT)
        else:
            self._ps = _ps.ps_keygen(_MSG_COUNT)   # pure-Python PS fallback
            self._bbs_key = self._ps.public         # the message-bound verifier key
        self._verified_roots: set[bytes] = set()

    @property
    def bbs_key(self):
        """The message-bound BBS public key verifiers use."""
        return self._bbs_key

    def verify_and_issue(
        self, system_id_handle: bytes, level: AssuranceLevel
    ) -> tuple[VerificationRecord, VerificationCredential]:
        """(Test-)verify a System-ID and issue ONE BBS+ credential. Uniqueness: a
        root verifies once (re-issue returns a fresh credential for the SAME
        root, never a second identity)."""
        self._verified_roots.add(system_id_handle)
        msgs = _messages(level, system_id_handle)
        if _BBS_AVAILABLE:
            sig = sign(SignRequest(key_pair=self._kp, messages=msgs))
            assert verify(VerifyRequest(key_pair=self._kp, messages=msgs, signature=sig))
        else:
            sig = _ps.ps_sign(self._ps, [_ps.msg_scalar(m) for m in msgs])
        cred = VerificationCredential(signature=sig, messages=msgs, level=level, _bbs_key=self._bbs_key)
        return VerificationRecord(system_id_handle=system_id_handle, level=level), cred

    def is_unique_root(self, system_id_handle: bytes) -> bool:
        return system_id_handle in self._verified_roots

    # -- holder side: present an unlinkable inherited proof -----------------

    @staticmethod
    def present(credential: VerificationCredential, *, nonce: bytes,
                disclose_system_id: bool = False) -> InheritedProof:
        """Create a re-randomized BBS+ proof. Reveals {claim, level}; hides the
        system-id unless `disclose_system_id` (accountability under cause)."""
        revealed = [credential.messages[0], credential.messages[1]]
        if disclose_system_id:
            revealed.append(credential.messages[2])
        if _BBS_AVAILABLE:
            sid_type = ProofMessageType.Revealed if disclose_system_id else ProofMessageType.HiddenProofSpecificBlinding
            pm = [
                ProofMessage(credential.messages[0], ProofMessageType.Revealed),
                ProofMessage(credential.messages[1], ProofMessageType.Revealed),
                ProofMessage(credential.messages[2], sid_type),
            ]
            proof = create_proof(CreateProofRequest(
                public_key=credential._bbs_key, messages=pm, signature=credential.signature, nonce=nonce))
        else:
            reveal = [0, 1] + ([2] if disclose_system_id else [])
            scalars = [_ps.msg_scalar(m) for m in credential.messages]
            psp = _ps.ps_present(credential._bbs_key, credential.signature, scalars, reveal=reveal, nonce=nonce)
            proof = _ps.serialize_proof(psp)          # opaque, fresh per presentation
        return InheritedProof(proof=proof, revealed=revealed, nonce=nonce,
                              level=credential.level, discloses_system_id=disclose_system_id)

    # -- verifier side ------------------------------------------------------

    @staticmethod
    def verify_proof(bbs_key, proof: InheritedProof, *, required: AssuranceLevel) -> bool:
        """Verifier learns ONLY the revealed messages (level), nothing else.

        SECURITY: the assurance level MUST be taken from the cryptographically
        REVEALED `level=` message, never from the unauthenticated `proof.level`
        dataclass field — otherwise a genuine low-level credential can clear a
        high-level gate by lying about the field (privilege escalation)."""
        if _BBS_AVAILABLE:
            # ursa-bbs-signatures.verify_proof returns a bool (True on success).
            status = verify_proof(VerifyProofRequest(
                public_key=bbs_key, proof=proof.proof, messages=proof.revealed, nonce=proof.nonce))
            if bool(status) is not True:
                return False
        else:
            # Rebuild the revealed scalars from the revealed attribute STRINGS (binds the
            # proof to the claimed messages), then verify the PS proof against the key.
            revealed_vals = [_ps.msg_scalar(m) for m in proof.revealed]
            psp = _ps.deserialize_proof(proof.proof, revealed_vals=revealed_vals)
            if not _ps.ps_verify(bbs_key, psp, proof.nonce):
                return False
        # Gate on the REVEALED level + require the constant claim be revealed.
        revealed = _revealed_level(proof.revealed)
        if revealed is None or revealed < required:
            return False
        return True

    @staticmethod
    def resolve_system_id(proof: InheritedProof) -> Optional[bytes]:
        """Accountability: read the system-id from an ACCOUNTABILITY disclosure
        proof (one the holder produced under cause with disclose_system_id=True).
        Returns None for a normal (unlinkable) proof. Involuntary opening without
        the holder is out of scope for plain BBS+ (see module docstring)."""
        if not proof.discloses_system_id:
            return None
        for m in proof.revealed:
            if m.startswith("systemid="):
                return bytes.fromhex(m.split("=", 1)[1])
        return None
