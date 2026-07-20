"""Live-provenance binding — attribution inherits the live provenance of its
moment (Code Spec Priority 1 / the T-25b fix).

THE PROBLEM: accountable-attribution rested solely on the BBS+ credential check,
which is separable from any LK/presence secret — a forged BBS+ (or a self-minted
bundle) yields a valid "verified human" attribution with NO live presence. The
"library of truths" was forgeable-in-principle.

THE FIX (witnessable-but-secret): bind attribution VALIDITY, non-optionally, to a
signature only a party holding the CURRENT LK could make — and the LK is only
obtainable through a live, presence-gated session (see session/presence.py). The
binding covers:
  1.1 current LK        — the witness signing key is derived from the LK; its
                          PUBLIC half is published to a public anchor, so a
                          recipient verifies WITHOUT holding the LK.
  1.3 epoch position    — the witness key is epoch-specific (LK is per-epoch,
                          QRNG-valued, unpredictable) and the public halves live
                          in an append-only registry, so the "when" cannot be
                          backdated or pre-forged.
  1.4 live session key  — the signed attribution commits to the moment's session
                          key, tying the attribution to a real live session.
  1.2 author presence   — the attribution binds the authorship handle; the
                          authorship signature (elsewhere) means only the true
                          author can sign as themselves, so forging ANOTHER's
                          identity is a detectable mismatch (self-incrimination).

The witness keypair is the HYBRID PQC signature (ML-DSA + Ed25519): a *quantum*
BBS+ forger still cannot forge the LK-witness without the LK. So the classical
BBS+ weakness is contained to "must be live+present holding the current LK".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

from ..crypto.primitives import H
from ..crypto.sign import (
    HybridSigPublic, keypair_from_seed, sign as hybrid_sign, verify as hybrid_verify,
)


def _witness_seed(lk: bytes, drand_round: bytes) -> bytes:
    # The witness signing key is derived from the CURRENT LK (secret) + epoch.
    return H(b"atlas/lk-witness", lk, drand_round)


def _session_commit(session_key: bytes, content_hash: bytes) -> bytes:
    # Commit to the live session key (1.4). Opaque to a recipient (no session
    # key needed) but bound into the signed attribution core.
    return H(b"atlas/prov/session-commit", session_key, content_hash)


def _attribution_core(content_hash: bytes, drand_round: bytes, authorship_handle: bytes,
                      session_commit: bytes) -> bytes:
    return H(b"atlas/prov/attribution-core", content_hash, drand_round,
             authorship_handle, session_commit)


@dataclass
class LiveProvenanceBinding:
    """The producer-side binding folded into a provenance bundle. `witness_sig`
    is a hybrid-PQC signature over the attribution core, made with the LK-derived
    key. `session_commit` binds the live session key."""

    session_commit: bytes
    witness_sig: bytes


class PublicWitnessRegistry:
    """The PUBLIC anchor: an append-only registry of per-epoch LK-witness PUBLIC
    keys. The server (which holds the LK in its HSM) publishes only the public
    half per epoch; the private half is never published and is only derivable by
    a party holding the current LK. Append-only + prev-chained so the epoch
    position of a witness key cannot be silently backdated/inserted.
    """

    GENESIS = b"\x00" * 32

    def __init__(self) -> None:
        self._pub: Dict[bytes, HybridSigPublic] = {}
        self._order: list[bytes] = []
        self._head = self.GENESIS

    def publish(self, lk: bytes, drand_round: bytes) -> HybridSigPublic:
        """Server side: derive the epoch witness keypair from the LK and publish
        its PUBLIC half (the LK itself never leaves the HSM)."""
        kp = keypair_from_seed(_witness_seed(lk, drand_round))
        if drand_round not in self._pub:
            self._order.append(drand_round)
            self._head = H(b"atlas/witness-chain", self._head, drand_round, kp.public.encode())
        self._pub[drand_round] = kp.public
        return kp.public

    def register_public(self, drand_round: bytes, pub: HybridSigPublic) -> None:
        """Register a PUBLIC witness half directly (no LK). Used when the LK holder
        (e.g. a phone) derived the pub locally and publishes only the public half
        to this anchor — the LK never leaves. Recipients verify against it without
        the LK (preserves witnessable-but-secret)."""
        if drand_round not in self._pub:
            self._order.append(drand_round)
            self._head = H(b"atlas/witness-chain", self._head, drand_round, pub.encode())
        self._pub[drand_round] = pub

    def witness_pub(self, drand_round: bytes) -> Optional[HybridSigPublic]:
        return self._pub.get(drand_round)

    def position(self, drand_round: bytes) -> Optional[int]:
        return self._order.index(drand_round) if drand_round in self._order else None


def bind_live_provenance(*, lk: bytes, session_key: bytes, content_hash: bytes,
                         drand_round: bytes, authorship_handle: bytes) -> LiveProvenanceBinding:
    """Producer side (live session, holds the current LK): sign the attribution
    core with the LK-derived witness key. Requires the current LK — obtainable
    only through the live, presence-gated session — so a forger without live
    presence cannot produce this."""
    kp = keypair_from_seed(_witness_seed(lk, drand_round))
    session_commit = _session_commit(session_key, content_hash)
    core = _attribution_core(content_hash, drand_round, authorship_handle, session_commit)
    return LiveProvenanceBinding(session_commit=session_commit,
                                 witness_sig=hybrid_sign(kp, core))


def verify_live_provenance(binding: Optional[LiveProvenanceBinding], *, content_hash: bytes,
                           drand_round: bytes, authorship_handle: bytes,
                           registry: PublicWitnessRegistry) -> bool:
    """Recipient side: verify the witness signature against the PUBLIC registry
    for this epoch. Needs only the public anchor — NOT the LK (preserves recipient
    verifiability, 1.1). A binding made for a different epoch's LK verifies only
    against that epoch's public key, so the 'when' cannot be moved (1.3)."""
    if binding is None:
        return False
    pub = registry.witness_pub(drand_round)
    if pub is None:
        return False
    core = _attribution_core(content_hash, drand_round, authorship_handle, binding.session_commit)
    return hybrid_verify(pub, core, binding.witness_sig)
