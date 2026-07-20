"""True-Self-Key identity tree and one-to-one verification (Locked Model §2.1-2.2).

CORRECTED IDENTITY MODEL (supersedes the earlier single-seed System-ID):

  The permanent TSK is ONE key, SPLIT into two halves:
    * a USER-HELD half (the Atlas Card / possession factor), and
    * a SERVER-HSM-HELD half (non-exportable, HSM-resident).
  There is NO separate System-ID secret. The System-ID is *reassembled* from
  BOTH halves — neither half alone reassembles it.

  Reassembly:
    * routine   — user half (Atlas Card) + server-HSM half.
    * recovery  — if the card is lost, the user half is reconstructed from an
                  x-of-n split of the System-ID-associated biometric held ACROSS
                  the distributed servers (never centrally; no single node holds
                  it), reclaimed only in a safe/controlled in-person setting;
                  then combined with the server-HSM half.

  Hierarchy:
    TSK  (permanent; split user-half + server-HSM-half — never whole post-genesis)
      -> System-ID  (reassembled from BOTH halves; blind, never surfaced)
         -> pseudonyms  (forward-derived; user-selected PUBLIC / PRIVATE /
                         ANONYMOUS tier per pseudonym)

Identifiers:
  * A static handle H(TSK_public) is the opaque standing identifier.
  * Per-context pseudonymity derives a different handle per context/tier.
  * The full public key is revealed only at a continuity event, where the
    verifier confirms it hashes to the known handle, then verifies the signature.

One-to-one verification: assert a handle (selector) -> retrieve that one identity
-> match the live biometric one-to-one (verify, not identify); the blind root is
never exposed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from ..crypto import shamir
from ..crypto.primitives import H, hkdf
from ..crypto.sign import (
    HybridSigKeypair,
    HybridSigPublic,
    keypair_from_seed,
    sphincs_keypair_from_seed,
    sphincs_sign,
    sphincs_verify,
    SPX_SEED_BYTES,
)

CHILD_CONTEXTS = ("real-id", "anonymous", "authorship", "recovery")


def handle_of(public_encoded: bytes) -> bytes:
    """Opaque standing identifier H(public) (§7.1)."""
    return H(b"atlas/handle", public_encoded)


# ---------------------------------------------------------------------------
# Split TSK  ->  reassembled System-ID  (Locked Model §2.1-2.2)
# ---------------------------------------------------------------------------

class PseudonymTier(Enum):
    """User-selected disclosure tier per pseudonym (identity / pseudonym /
    anonymity tiers)."""
    PUBLIC = "public"
    PRIVATE = "private"
    ANONYMOUS = "anonymous"


def _tsk_halves(tsk_seed: bytes, *, rotation: int = 0) -> tuple[bytes, bytes]:
    """Split the permanent TSK into a user-held half (Atlas Card) and a
    server-HSM-held half. Deterministic AT GENESIS only; post-genesis the whole
    seed is destroyed and neither party holds both halves."""
    salt = b"" if rotation == 0 else b"/v" + str(rotation).encode()
    user_half = hkdf(ikm=tsk_seed, info=b"atlas/tsk/user-half" + salt, length=32)
    server_half = hkdf(ikm=tsk_seed, info=b"atlas/tsk/server-half" + salt, length=32)
    return user_half, server_half


def reassemble_system_id(user_half: bytes, server_half: bytes) -> bytes:
    """The blind System-ID, reassembled from BOTH halves. Neither half alone can
    compute it (each is an independent 32-byte secret; the KDF needs both)."""
    return hkdf(ikm=user_half + server_half, info=b"atlas/system-id/reassembled", length=32)


class ServerHSM:
    """Models the (distributed) server HSM holding the server half of a split TSK.
    It participates in System-ID reassembly but exposes NO accessor for its half.

    HONEST BOUNDARY: true non-exportability is a hardware-HSM property (the key
    physically cannot leave tamper-resistant hardware); Python cannot enforce it,
    so this models the API contract (no method returns the half), not memory
    protection. Same hardware-gated boundary as the Secure Enclave."""

    def __init__(self, server_half: bytes):
        self.__server_half = server_half            # non-exportable (no accessor)

    def reassemble_system_id(self, user_half: bytes) -> bytes:
        """Combine the caller's user half with the sealed server half. The server
        half never leaves the HSM; only the reassembled System-ID is returned."""
        return reassemble_system_id(user_half, self.__server_half)


def split_user_half_for_recovery(user_half: bytes, *, n: int = 5, k: int = 3) -> List[shamir.Share]:
    """x-of-n split of the (biometric-associated) user half, distributed ACROSS
    servers for card-loss recovery — no single node holds it."""
    return shamir.split(user_half, n=n, k=k)


def reconstruct_user_half(shares: List[shamir.Share]) -> bytes:
    """Reconstruct the user half from >= k distributed shares (safe-setting,
    in-person card-loss recovery)."""
    return shamir.combine(shares)


@dataclass
class Child:
    context: str
    keypair: HybridSigKeypair
    index: int = 0

    @property
    def public(self) -> HybridSigPublic:
        return self.keypair.public

    @property
    def handle(self) -> bytes:
        return handle_of(self.public.encode())


@dataclass
class Profile:
    """A PERSONA — a top-level compartment under the blind System-ID that owns its OWN
    full stack (vault, messaging, forum, …). Its PUBLIC identity is `identity.handle`;
    `username` is only the human label a person chooses for it. The System-ID link never
    surfaces. Distinct (username, tier) -> a distinct, mutually UNLINKABLE persona, so a
    pseudonym ("horseshit") cannot be tied to the real you or to your other personas by
    anyone who only sees the handles. ONE persona may be CERTIFIED (Real-ID verified); the
    rest stay pseudonymous.

    Every per-feature slice derives UNDER the persona seed, so even one persona's own
    surfaces (its messaging vs its vault) don't cross-link to an observer."""

    username: str
    tier: PseudonymTier
    identity: Child                        # the persona's signing identity; its handle IS the persona
    _seed: bytes = field(repr=False, default=b"")   # per-persona root; parent of every feature slice

    @property
    def handle(self) -> bytes:
        """The persona's public, opaque standing handle (what a relay / forum sees)."""
        return self.identity.handle

    def feature(self, feature: str) -> Child:
        """A per-feature slice of THIS persona (e.g. 'messaging', 'vault', 'forum').
        Its own one-way handle, unlinkable to the persona's other features or to any
        other persona by anyone who only holds the handle."""
        seed = hkdf(ikm=self._seed, info=b"atlas/feature/" + feature.encode(), length=32)
        return Child(context=f"{self.username}/{feature}", keypair=keypair_from_seed(seed))


@dataclass
class IdentityTree:
    """A user's full identity tree. The System-ID is REASSEMBLED from both TSK
    halves (user card + server HSM); the reassembled value is the blind root and
    only handles / (at continuity events) public keys are surfaced.

    `_user_half` is the card factor; `_server_hsm` holds the non-exportable server
    half. `_system_id_secret` is the reassembled System-ID cached for derivation
    (in deployment it is ephemeral, held only while a session is being set up)."""

    tsk_seed: bytes                      # 32B+ root seed (whole TSK; genesis only)
    tsk_public: bytes                    # SPHINCS+ public root
    _tsk_secret: bytes = field(repr=False)
    _system_id_secret: bytes = field(repr=False)   # REASSEMBLED from both halves
    _user_half: bytes = field(repr=False, default=b"")
    _server_hsm: Optional["ServerHSM"] = field(repr=False, default=None)
    children: Dict[str, Child] = field(default_factory=dict)
    rotation: int = 0                    # System-ID re-rooting generation (§5)

    @property
    def root_handle(self) -> bytes:
        """Static standing identifier H(TSK_public) (§7.1)."""
        return handle_of(self.tsk_public)

    def system_id_handle(self) -> bytes:
        """Handle of the blind System-ID. The secret itself is never exposed."""
        return H(b"atlas/system-id-handle", self._system_id_secret)

    def child(self, context: str) -> Child:
        if context not in self.children:
            raise KeyError(context)
        return self.children[context]

    def pseudonym(self, label: str, tier: PseudonymTier) -> Child:
        """Derive a user-defined pseudonym (PUBLIC / PRIVATE / ANONYMOUS tier)
        forward from the reassembled System-ID. Distinct label or tier -> distinct,
        unlinkable pseudonym."""
        seed = hkdf(ikm=self._system_id_secret,
                    info=b"atlas/pseudonym/" + tier.value.encode() + b"/" + label.encode(),
                    length=32)
        return Child(context=f"{tier.value}:{label}", keypair=keypair_from_seed(seed))

    def profile(self, username: str, tier: PseudonymTier = PseudonymTier.ANONYMOUS) -> Profile:
        """Derive a PERSONA (top-level compartment) from the blind System-ID. The persona's
        identity and ALL its feature slices hang off a per-persona seed, so personas are
        mutually unlinkable and unlinkable to the real you — only the holder of the System-ID
        can prove two personas are the same person. Use tier=PUBLIC for a persona you intend to
        certify as the real, verified you; ANONYMOUS for a throwaway pseudonym ('horseshit')."""
        seed = hkdf(ikm=self._system_id_secret,
                    info=b"atlas/profile/" + tier.value.encode() + b"/" + username.encode(),
                    length=32)
        identity_seed = hkdf(ikm=seed, info=b"atlas/profile/identity", length=32)
        identity = Child(context=f"profile:{tier.value}:{username}",
                         keypair=keypair_from_seed(identity_seed))
        return Profile(username=username, tier=tier, identity=identity, _seed=seed)

    # -- continuity event: reveal-and-verify (§7.1) --------------------------

    def sign_continuity(self, message: bytes) -> bytes:
        """The TSK signs re-enrolment / continuity (§2.1 'Root only')."""
        kp = sphincs_keypair_from_seed(self._tsk_secret[:SPX_SEED_BYTES])
        return sphincs_sign(kp, message)


def _seed32(material: bytes) -> bytes:
    return material[:32]


def build_identity_tree(tsk_seed: bytes, *, rotation: int = 0,
                        server_hsm: Optional[ServerHSM] = None) -> IdentityTree:
    """Genesis: construct the tree from a (QRNG-seeded) whole TSK (§6, §2.1).

    The whole TSK exists only transiently at genesis (paper -> Atlas Card). It is
    SPLIT into a user-held half and a server-HSM half; the System-ID is then
    REASSEMBLED from both (neither half alone reassembles it). Post-genesis the
    seed is destroyed: the user holds the card half, the HSM holds the server half.

    `server_hsm` lets a caller supply the HSM that already holds the server half
    (the normal case after genesis); if omitted, genesis creates one and seals
    the deterministically-split server half into it.

    `rotation` is the System-ID re-rooting generation: the TSK (and root_handle)
    is DURABLE across re-roots; only the System-ID (and thus pseudonyms) rotate.
    """
    if len(tsk_seed) < 32:
        raise ValueError("tsk_seed must be >= 32 bytes")
    # TSK SPHINCS+ keypair from a domain-separated SPHINCS+ seed (rotation-independent).
    spx_seed = hkdf(ikm=tsk_seed, info=b"atlas/tsk/spx", length=SPX_SEED_BYTES)
    tsk = sphincs_keypair_from_seed(spx_seed)

    # Split the whole TSK; reassemble the blind System-ID from BOTH halves.
    user_half, server_half = _tsk_halves(tsk_seed, rotation=rotation)
    hsm = server_hsm or ServerHSM(server_half)
    system_id_secret = hsm.reassemble_system_id(user_half)   # needs both halves

    tree = IdentityTree(
        tsk_seed=tsk_seed,
        tsk_public=tsk.pk,
        _tsk_secret=spx_seed,
        _system_id_secret=system_id_secret,
        _user_half=user_half,
        _server_hsm=hsm,
        rotation=rotation,
    )
    # Forward-derive each fixed child from the reassembled System-ID.
    for ctx in CHILD_CONTEXTS:
        child_seed = hkdf(
            ikm=system_id_secret, info=b"atlas/child/" + ctx.encode() + b"/0", length=32
        )
        tree.children[ctx] = Child(context=ctx, keypair=keypair_from_seed(child_seed), index=0)
    return tree


# ---------------------------------------------------------------------------
# One-to-one verification (§7.1)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VerificationResult:
    matched_handle: bool
    signature_valid: bool
    biometric_matched: bool

    @property
    def ok(self) -> bool:
        return self.matched_handle and self.signature_valid and self.biometric_matched


def verify_one_to_one(
    *,
    asserted_handle: bytes,
    revealed_public: HybridSigPublic,
    challenge: bytes,
    signature: bytes,
    live_biometric_matches: bool,
) -> VerificationResult:
    """Selector -> retrieve one identity -> verify (not identify).

    1. Confirm the revealed public key hashes to the asserted handle.
    2. Verify the signature over the challenge.
    3. Match the live biometric one-to-one (caller supplies the comparison; the
       Secure Enclave on device, or the live recovery person at total loss).
    The blind System-ID root is never touched.
    """
    from ..crypto.sign import verify as sig_verify

    matched = handle_of(revealed_public.encode()) == asserted_handle
    sig_ok = matched and sig_verify(revealed_public, challenge, signature)
    return VerificationResult(
        matched_handle=matched,
        signature_valid=sig_ok,
        biometric_matched=bool(live_biometric_matches),
    )
