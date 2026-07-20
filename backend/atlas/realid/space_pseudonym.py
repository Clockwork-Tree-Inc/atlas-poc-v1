"""Per-scope (space) pseudonyms + personhood (TRUST_LAYER.md #13).

One root identity → many scope-bound pseudonyms:

    space_nym       = PRF(root_secret, space_id)   # who you are *inside* a space
    space_nullifier = PRF(root_secret, space_id)   # one-per-human-per-space marker (domain-sep)

Properties:
  * STABLE within a space — the family/workplace sees a consistent you across sessions.
  * UNLINKABLE across spaces — a different `space_id` yields an unrelated nym/nullifier; nobody
    can correlate your identities in two spaces.
  * NON-REVEALING of the root — one-way H; a nym/nullifier never leaks the root or the human.
  * SYBIL-RESISTANT — two layers: (a) nym and nullifier are DETERMINISTIC functions of
    (root, space), so ONE root = exactly one identity per space (no self-sybil); and (b)
    `SpaceRegistry.register` REQUIRES a `PersonhoodAuthority` membership proof that the root is a
    verified unique human, so a stranger cannot mint identities from arbitrary/fake roots. Without
    (b), (a) alone does NOT stop "1000 fake roots → 1000 identities"; the gate is what makes
    "one identity per real human" real.

The **nullifier** is domain-separated from the **nym**, so a space can publish/track nullifiers
for sybil-resistance without those revealing (or being linkable to) the nyms people present.

Hash-based ⇒ already POST-QUANTUM (only the anonymous *attribute* credential uses pairings).
Composes with the verified System-ID for accountability: `root_secret` descends from the
System-ID, so an authority can still resolve "under cause" — linkage is an authorized relation,
never a static shared identifier.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from ..crypto.primitives import H
from ..ledger import merkle

_NYM = b"atlas/space-nym"
_NULLIFIER = b"atlas/space-nullifier"
_PERSONHOOD = b"atlas/personhood-commit"


class SybilError(Exception):
    """A nullifier was presented with a different nym than first seen — a malformed or forged
    membership (honest derivation is deterministic, so this cannot happen by accident)."""


class PersonhoodError(Exception):
    """A join was attempted without a valid proof that the root is a verified unique human."""


def _lp(b: bytes) -> bytes:
    """Length-prefix framing (matches the repo's `hkdf_combine` discipline) so adjacent
    variable-length fields cannot collide: H(_NYM, "ab", "c") must not equal H(_NYM, "a", "bc")."""
    return len(b).to_bytes(4, "big") + b


def space_nym(root_secret: bytes, space_id: bytes) -> bytes:
    """PRF(root, space): your stable-in-space, unlinkable-across-space handle. One-way."""
    return H(_NYM, _lp(root_secret), _lp(space_id))


def space_nullifier(root_secret: bytes, space_id: bytes) -> bytes:
    """One-per-human-per-space marker (domain-separated from the nym). Same (root, space) →
    same nullifier, so a person holds at most ONE identity per space; unlinkable across spaces;
    reveals neither the root nor which human."""
    return H(_NULLIFIER, _lp(root_secret), _lp(space_id))


# --------------------------------------------------------------------------- personhood
def personhood_commitment(root_secret: bytes) -> bytes:
    """A commitment to a person's root, enrolled ONCE in the verified-humans set. Hides the root."""
    return H(_PERSONHOOD, _lp(root_secret))


class PersonhoodAuthority:
    """The verified-humans set — a Merkle accumulator of `personhood_commitment`s. A person is
    enrolled once (via an accountable enrollment tied to the verified System-ID). `root_digest` is
    the published, trusted commitment to the whole set; a `membership_proof` shows a root is in it
    without the verifier re-enrolling. This is the gate that stops unlimited fake roots."""

    def __init__(self) -> None:
        self._commitments: List[bytes] = []

    def enroll(self, root_secret: bytes) -> None:
        c = personhood_commitment(root_secret)
        if c not in self._commitments:
            self._commitments.append(c)

    @property
    def root_digest(self) -> bytes:
        return merkle.merkle_root(self._commitments)

    def membership_proof(self, root_secret: bytes) -> list[merkle.ProofStep]:
        c = personhood_commitment(root_secret)
        if c not in self._commitments:
            raise PersonhoodError("root is not enrolled as a verified human")
        return merkle.inclusion_proof(self._commitments, self._commitments.index(c))


def verify_personhood(root_secret: bytes, proof: list[merkle.ProofStep],
                      authority_root: bytes) -> bool:
    """Verify that `root_secret` is a verified unique human — its personhood commitment is in the
    authority's Merkle set. NOTE: this reveals the personhood commitment to the verifier (the space
    host); a fully host-unlinkable variant proves the same statement in ZK (composes with the
    zk-personhood proof), revealing only the per-space nullifier."""
    return merkle.verify_inclusion(personhood_commitment(root_secret), proof, authority_root)


@dataclass(frozen=True)
class SpaceMembership:
    """What a user mints to join a space. `nym` is presented; `nullifier` is published for the
    space's sybil check. Neither reveals the root, and the two are mutually unlinkable."""

    space_id: bytes
    nym: bytes
    nullifier: bytes


def join_space(root_secret: bytes, space_id: bytes) -> SpaceMembership:
    """Mint a space membership from your root — a space-nym, NOT the root."""
    return SpaceMembership(space_id=space_id,
                           nym=space_nym(root_secret, space_id),
                           nullifier=space_nullifier(root_secret, space_id))


class SpaceRegistry:
    """A space's membership set with real sybil resistance: registration REQUIRES a proof that the
    root is a verified unique human (`PersonhoodAuthority`), and the nym/nullifier are DERIVED from
    that verified root — never accepted from the caller. So `n` unverified roots admit `0`, and a
    forged `(nym, nullifier)` cannot register. One nullifier per space ⇒ one identity per human."""

    def __init__(self, space_id: bytes, authority_root: bytes) -> None:
        self.space_id = space_id
        self.authority_root = authority_root      # the trusted verified-humans set digest
        self._nym_of: dict[bytes, bytes] = {}     # nullifier -> nym

    def register(self, root_secret: bytes, membership_proof: list[merkle.ProofStep]) -> bytes:
        """Admit a verified human. Verifies personhood, then derives the per-space nym/nullifier
        from the verified root. Idempotent per human. Returns the admitted nym."""
        if not verify_personhood(root_secret, membership_proof, self.authority_root):
            raise PersonhoodError("root is not a verified unique human (membership proof failed)")
        nullifier = space_nullifier(root_secret, self.space_id)
        nym = space_nym(root_secret, self.space_id)
        seen = self._nym_of.get(nullifier)
        if seen is not None:
            if seen != nym:                       # cannot happen with honest derivation
                raise SybilError("nullifier reused with a different nym")
            return nym                            # idempotent re-join; still one identity
        self._nym_of[nullifier] = nym
        return nym

    def is_member(self, nym: bytes) -> bool:
        return nym in self._nym_of.values()

    def size(self) -> int:
        return len(self._nym_of)
