"""Authorship signing and provenance bundle (§8.1, §10.2 capstone).

Sign content with a liveness-gated authorship pseudonym (the System-ID
'authorship' child) — never the TSK, LK, or DevKey. Routine signatures use
ML-DSA+Ed25519.

LOAD-BEARING GUARANTEE (accountability reframe): provenance's verdict is
**accountable attribution** — "this content is bound to a verified-human
pseudonym, resolvable under cause" — NOT scene-authenticity. The verdict rests
on: integrity (unmodified), the authorship pseudonym (handle + signature), a
verified-live human author (liveness, optionally an inherited L1 "a verified real
human is behind this" proof), a verifiable time, and a ledger anchor. The
pseudonym is resolvable to the accountable System-ID only under cause
(`resolve_author_under_cause`), reusing the Real-ID verification machinery.

PAD is an ADVISORY fraud signal, not the guarantee. It still runs (and can
optionally reject obvious fakes at capture), and its result rides along as a
confidence hint — but the analog-hole problem (proving the camera saw a real
scene) is explicitly NOT what the system claims. A staged scene still carries the
author's accountable pseudonym; that accountability is the product.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..beacon.base import BeaconRound
from ..crypto.primitives import H
from ..crypto.sign import HybridSigPublic, sign, verify
from ..keys.identity import Child, handle_of
from ..liveness.attestation import AttestationSubsystem, LivenessAttestation
from ..liveness.bayes import PoLEState
from ..realid.levels import AssuranceLevel
from ..realid.verification import (
    AtlasVerificationAuthority, InheritedProof, VerificationCredential,
)
from .ledger import AnchorReceipt, LedgerStub
from .live_binding import (
    LiveProvenanceBinding, PublicWitnessRegistry, bind_live_provenance,
    verify_live_provenance,
)
from .pad import PADRejected, PADResult, pad_check


class NotLiveError(Exception):
    """Author was not verified-live at signing time — authorship is refused."""


# Capture-binding domain separators. The inherited verification proof and the
# liveness attestation are bound to THIS author + THIS content + THIS epoch, so
# neither can be transplanted from another author/capture (see the security note
# on verify_provenance).
_LIVENESS_BIND = b"atlas/provenance/liveness-binding"
_INHERITED_BIND = b"atlas/provenance/inherited-binding"


def _capture_binding(label: bytes, authorship_handle: bytes, content_hash: bytes,
                     drand_round: bytes) -> bytes:
    return H(label, authorship_handle, content_hash, drand_round)


@dataclass(frozen=True)
class CaptureMetadata:
    """Bound at capture, before the image leaves the capture context (§8.2)."""

    camera_intrinsics: str
    motion: str
    captured_at: str
    depth_summary: str

    def canonical(self) -> bytes:
        import json
        return json.dumps(self.__dict__, sort_keys=True, separators=(",", ":")).encode()


@dataclass
class ProvenanceBundle:
    content_hash: bytes
    authorship_handle: bytes
    authorship_public: HybridSigPublic
    metadata: CaptureMetadata
    drand_round: bytes
    epoch_randomness: bytes
    pad: PADResult                          # advisory signal, not the verdict
    liveness: LivenessAttestation
    signature: bytes
    anchor_index: int
    verification_proof: Optional[InheritedProof] = None  # inherited "verified human behind this"
    live_binding: Optional[LiveProvenanceBinding] = None  # LK/session/epoch live-provenance binding

    def transcript(self) -> bytes:
        # The authorship signature binds the content, metadata, time, liveness,
        # the authorship handle, AND (when present) the inherited verification
        # proof — so a proof can't be swapped onto another bundle. The PAD digest
        # is bound too (tamper-evidence) but the VERDICT does not rest on it.
        vp = b""
        if self.verification_proof is not None:
            vp = H(b"vp", bytes([int(self.verification_proof.level)]),
                   self.verification_proof.nonce, self.verification_proof.proof)
        lb = b""
        if self.live_binding is not None:
            lb = H(b"lb", self.live_binding.session_commit, self.live_binding.witness_sig)
        return H(
            b"atlas/provenance",
            self.content_hash,
            self.metadata.canonical(),
            self.drand_round,
            self.epoch_randomness,
            self.pad.digest(),
            self.liveness.pole_digest,
            self.liveness.challenge,           # bind the capture-freshness nonce
            self.authorship_handle,
            vp,
            lb,                                # bind the live-provenance binding
        )


@dataclass
class ProvenanceVerdict:
    # accountable-attribution checks (load-bearing):
    integrity_ok: bool          # content unmodified since capture
    handle_ok: bool             # authorship public matches the handle
    signature_ok: bool          # signed by the authorship pseudonym
    liveness_ok: bool           # authored by a verified live human, time-bound
    anchored_ok: bool           # content hash anchored in the ledger
    verification_inherited_ok: bool  # if required: "a verified real human is behind this"
    live_provenance_ok: bool = True  # bound to the live LK/session/epoch of its moment
    # advisory (NOT part of the guarantee):
    pad_advisory: PADResult = None
    reasons: tuple[str, ...] = field(default_factory=tuple)

    @property
    def accountable(self) -> bool:
        """The load-bearing guarantee: bound to an accountable verified-human
        pseudonym AND to the live provenance (LK/session/epoch) of its moment —
        so a forged credential alone (no live presence + current LK) is NOT
        sufficient. Resolvable under cause."""
        return all([self.integrity_ok, self.handle_ok, self.signature_ok,
                    self.liveness_ok, self.anchored_ok, self.verification_inherited_ok,
                    self.live_provenance_ok])

    @property
    def ok(self) -> bool:
        # Accountable attribution is the verdict. PAD does not gate it.
        return self.accountable


def sign_capture(
    *,
    content: bytes,
    depth_map,
    moire_score: float,
    metadata: CaptureMetadata,
    authorship: Child,
    attestation_subsystem: AttestationSubsystem,
    pole: PoLEState,
    beacon_round: BeaconRound,
    ledger: LedgerStub,
    lk: bytes,
    session_key: bytes,
    verification_credential: Optional[VerificationCredential] = None,
    pad_policy: str = "advisory",
) -> ProvenanceBundle:
    """Capture-time signing. Requires a verified-live author; anchors the hash;
    signs the earliest frame with the authorship pseudonym.

    LIVE-PROVENANCE BINDING (Priority 1 / T-25b): the attribution is bound
    non-optionally to the live provenance of this moment. `lk` (the current
    presence-gated Living Key) and `session_key` (the moment's live session) are
    folded into a witnessable-but-secret binding — the producer signs with a key
    derived from the LK, whose PUBLIC half a recipient verifies against a public
    registry WITHOUT the LK. A forged credential without the current LK (i.e.
    without live presence) cannot produce a valid attribution.

    BINDING (security): the liveness attestation and any inherited verification
    proof are produced HERE, bound to (authorship handle, content hash, epoch) —
    so neither can be a stranger's credential transplanted onto this capture. The
    caller supplies the author's own `attestation_subsystem` + live `pole` and,
    optionally, the author's own `verification_credential`; sign_capture mints the
    capture-bound attestation/proof rather than accepting pre-made ones.

    `pad_policy`:
      * "advisory" (default) — PAD runs and is attached, but never blocks signing.
        Accountability is the guarantee; PAD is a confidence hint.
      * "reject" — additionally refuse to sign an obvious fake at capture (the
        fraud-filter bonus; e.g. the §10.2 screen-replay demo).
    """
    pad = pad_check(depth_map=depth_map, moire_score=moire_score)
    if pad_policy == "reject" and not pad.passed:
        raise PADRejected("; ".join(pad.reasons) or "PAD failed")

    content_hash = H(b"atlas/content", content)
    drand_round = beacon_round.drand_round()

    # Liveness bound to THIS capture: the author's Enclave attests over a
    # challenge derived from (author, content, epoch) — a captured attestation
    # from another capture answers the wrong challenge and is rejected.
    live_challenge = _capture_binding(_LIVENESS_BIND, authorship.handle, content_hash, drand_round)
    attestation = attestation_subsystem.attest(pole, challenge=live_challenge)
    if attestation is None or not (attestation.verify() and attestation.operate):
        raise NotLiveError("author not verified-live at capture")

    # Inherited "a verified human is behind this" proof bound to the SAME author:
    # the BBS+ nonce is the binding channel, so a stranger's proof (bound to their
    # own author/content) cannot be transplanted onto this bundle.
    verification_proof = None
    if verification_credential is not None:
        vnonce = _capture_binding(_INHERITED_BIND, authorship.handle, content_hash, drand_round)
        verification_proof = AtlasVerificationAuthority.present(verification_credential, nonce=vnonce)

    # Live-provenance binding: sign the attribution core with the LK-derived
    # witness key (needs the current LK — obtainable only via a live, presence-
    # gated session) and commit to the live session key.
    live_binding = bind_live_provenance(
        lk=lk, session_key=session_key, content_hash=content_hash,
        drand_round=drand_round, authorship_handle=authorship.handle)

    receipt = ledger.anchor(content_hash)
    bundle = ProvenanceBundle(
        content_hash=content_hash,
        authorship_handle=authorship.handle,
        authorship_public=authorship.public,
        metadata=metadata,
        drand_round=drand_round,
        epoch_randomness=beacon_round.randomness,
        pad=pad,
        liveness=attestation,
        signature=b"",
        anchor_index=receipt.index,
        verification_proof=verification_proof,
        live_binding=live_binding,
    )
    bundle.signature = sign(authorship.keypair, bundle.transcript())
    return bundle


def verify_provenance(
    bundle: ProvenanceBundle,
    *,
    content: bytes,
    ledger: LedgerStub,
    witness_registry: PublicWitnessRegistry,
    asserted_handle: Optional[bytes] = None,
    authority_bbs_key=None,
    required_level: AssuranceLevel = AssuranceLevel.L0,
) -> ProvenanceVerdict:
    """Recipient-side verification. The verdict is ACCOUNTABLE ATTRIBUTION:
    authored by a verified live human (and, if `required_level` >= L1, a proof
    that a verified real human is behind the pseudonym — without exposing the ID),
    at a verifiable time, integrity confirmed, anchored. PAD is advisory."""
    reasons = []

    integrity_ok = H(b"atlas/content", content) == bundle.content_hash
    if not integrity_ok:
        reasons.append("content modified since capture (hash mismatch)")

    handle_ok = handle_of(bundle.authorship_public.encode()) == bundle.authorship_handle
    if asserted_handle is not None and bundle.authorship_handle != asserted_handle:
        handle_ok = False
        reasons.append("authorship handle does not match the asserted author")

    signature_ok = handle_ok and verify(bundle.authorship_public, bundle.transcript(), bundle.signature)
    if not signature_ok:
        reasons.append("authorship signature invalid")

    # Liveness must be bound to THIS capture, not just this epoch: the attestation
    # challenge must equal the (author, content, epoch) binding. Without this a
    # captured genuine attestation is replayable onto fabricated content.
    expected_live_challenge = _capture_binding(
        _LIVENESS_BIND, bundle.authorship_handle, bundle.content_hash, bundle.drand_round)
    liveness_ok = (
        bundle.liveness.verify()
        and bundle.liveness.operate
        and bundle.liveness.drand_round == bundle.drand_round
        and bundle.liveness.challenge == expected_live_challenge
    )
    if not liveness_ok:
        reasons.append("author not verified-live / attestation not bound to this capture")

    # Inherited "a verified real human is behind this" (L1+), ID NOT revealed.
    # SECURITY (accountable attribution): the proof must be bound to THIS author —
    # its BBS+ nonce must equal the (author, content, epoch) binding. Otherwise a
    # stranger's valid proof can be TRANSPLANTED onto attacker-authored content,
    # laundering a verified-human verdict and pointing accountability at the wrong
    # person. The nonce binding ties "a verified human is behind THIS pseudonym."
    verification_inherited_ok = True
    if required_level >= AssuranceLevel.L1:
        expected_vnonce = _capture_binding(
            _INHERITED_BIND, bundle.authorship_handle, bundle.content_hash, bundle.drand_round)
        if bundle.verification_proof is None or authority_bbs_key is None:
            verification_inherited_ok = False
            reasons.append(f"level >= {required_level.name} required but no inherited verification proof")
        elif bundle.verification_proof.nonce != expected_vnonce:
            verification_inherited_ok = False
            reasons.append("inherited proof not bound to this author/content (transplant rejected)")
        elif not AtlasVerificationAuthority.verify_proof(
                authority_bbs_key, bundle.verification_proof, required=required_level):
            verification_inherited_ok = False
            reasons.append("inherited BBS+ verification proof invalid / insufficient level")

    anchored_ok = ledger.contains(bundle.content_hash) and ledger.verify_chain()
    if not anchored_ok:
        reasons.append("content hash not anchored / ledger chain broken")

    # Live-provenance (Priority 1 / T-25b): the attribution must be bound to the
    # live LK/session/epoch of its moment — a forged credential without the
    # current LK (no live presence) cannot produce this. Verified against the
    # PUBLIC witness registry, so a recipient needs no LK.
    live_provenance_ok = verify_live_provenance(
        bundle.live_binding, content_hash=bundle.content_hash, drand_round=bundle.drand_round,
        authorship_handle=bundle.authorship_handle, registry=witness_registry)
    if not live_provenance_ok:
        reasons.append("not bound to a live session / current LK (live-provenance binding invalid)")

    if not bundle.pad.passed:
        reasons.append("ADVISORY: PAD flagged a possible presentation attack (not a verdict gate)")

    return ProvenanceVerdict(
        live_provenance_ok=live_provenance_ok,
        integrity_ok=integrity_ok, handle_ok=handle_ok, signature_ok=signature_ok,
        liveness_ok=liveness_ok, anchored_ok=anchored_ok,
        verification_inherited_ok=verification_inherited_ok,
        pad_advisory=bundle.pad, reasons=tuple(reasons),
    )


def resolve_author_under_cause(authority_bbs_key, accountability_proof) -> Optional[bytes]:
    """Resolve the authorship pseudonym to the accountable System-ID under cause.

    With real BBS+, the normal inherited proof in the bundle is UNLINKABLE — the
    issuer cannot open it (that is the property). Accountability is therefore a
    HOLDER DISCLOSURE: under cause, the holder produces a full-disclosure BBS+
    proof (disclose_system_id=True) that reveals the System-ID. This verifies it
    and returns the System-ID. Holder-disclosure is ABSOLUTE by decision
    (Credential PQC Posture §6): a designated opener is rejected, not deferred —
    no operator/court/system key can open an unlinkable proof."""
    if accountability_proof is None or not accountability_proof.discloses_system_id:
        return None
    if not AtlasVerificationAuthority.verify_proof(
            authority_bbs_key, accountability_proof, required=AssuranceLevel.L1):
        return None
    return AtlasVerificationAuthority.resolve_system_id(accountability_proof)
