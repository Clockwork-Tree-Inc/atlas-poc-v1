"""Post-quantum, hash-based "verified unique human" personhood proof — REFERENCE SIMULATION.

    !!! THIS IS A REFERENCE SIMULATION / MODEL, NOT PRODUCTION CRYPTOGRAPHY !!!

Goal
----
Model the post-quantum alternative to a classical BBS/PS anonymous credential using
only HASH-BASED components (the ingredients a STARK/FRI system is actually built from):

  * a Merkle **registry** of verified-human *System-ID commitments*,
  * a Merkle **authentication path** as the "membership witness",
  * a per-context **nullifier** = H(System_ID, context),
  * an assurance **level L** bound into each commitment.

The statement being proven is:

    "I know a secret System_ID (and its opening) whose commitment is a leaf of the
     verified-human Merkle tree with root R; this pseudonym `nullifier` derives from
     that same System_ID and the given `context`; and the assurance level bound into
     my commitment is >= the required level."

...all WITHOUT revealing *which* System-ID / which leaf.

The honest gap (read this)
--------------------------
In a REAL deployment the membership witness is a **zero-knowledge (STARK/FRI) proof**
of the statement above. The verifier learns only the PUBLIC inputs:
    (root R, context, nullifier, required_level, verdict=true).
Everything else — System_ID, the opening `blind`, the exact level, the leaf value, and
crucially the **leaf index / Merkle path** — is HIDDEN inside the proof.

This module cannot build a real STARK (far too heavy for a PoC), so it MODELS the
statement by carrying the witness (System_ID, blind, level, leaf, path, index) in
plaintext inside `MembershipWitness` and re-executing the "circuit" (recompute leaf,
walk the Merkle path, recompute nullifier, compare level) during `verify_statement`.

That re-execution is faithful to *what is proven* but is NOT zero-knowledge: the
plaintext path reveals the leaf index and the plaintext witness reveals the System_ID.
To keep the privacy properties testable we therefore split every proof into:

  * `PublicInputs`  — exactly what a real STARK verifier would see, and
  * `MembershipWitness` — the private data a real STARK would HIDE.

The unlinkability / secrecy tests are asserted against `PublicInputs` ONLY, i.e. against
the information a real ZK verifier is allowed to have. See STARK_COST_NOTES at the
bottom for the size / prove-time estimate and the phone-vs-computer feasibility read.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

# --- reuse the Atlas protocol hash (SHA3-256) --------------------------------
# Run from backend/ with '.' on sys.path; add it defensively so the module also
# imports when executed directly.
_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from atlas.crypto import primitives  # noqa: E402

H = primitives.H  # SHA3-256, post-quantum-flavoured (Grover only halves the security)

# Domain-separation tags so a commitment can never be reinterpreted as a tree node,
# a nullifier, etc. (prevents cross-structure second-preimage tricks).
_TAG_COMMIT = b"atlas/zkpp/commit/v1"
_TAG_NODE = b"atlas/zkpp/node/v1"
_TAG_LEAF = b"atlas/zkpp/leaf/v1"
_TAG_NULL = b"atlas/zkpp/nullifier/v1"


def _lvl_bytes(level: int) -> bytes:
    if level < 0 or level > 0xFFFF:
        raise ValueError("level out of range [0, 65535]")
    return level.to_bytes(2, "big")


# ---------------------------------------------------------------------------
# System-ID commitment  (binds System_ID + assurance level L + opening)
# ---------------------------------------------------------------------------
def commit(system_id: bytes, level: int, blind: bytes) -> bytes:
    """Commitment to a verified human: binds the secret System_ID, its assurance
    level L, and a random opening `blind`.

    Hiding: `blind` (high-entropy) makes the commitment reveal nothing about
    System_ID. Binding: SHA3-256 collision resistance ties it to exactly one
    (System_ID, level) opening. This is the *leaf payload* of the Merkle tree.
    """
    return H(_TAG_COMMIT, system_id, _lvl_bytes(level), blind)


def leaf_hash(commitment: bytes) -> bytes:
    """Tree leaf = H(tag_leaf, commitment). Distinct tag from internal nodes."""
    return H(_TAG_LEAF, commitment)


def nullifier(system_id: bytes, context: bytes) -> bytes:
    """Per-context pseudonym: deterministic in (System_ID, context).

    * Deterministic -> one System_ID yields exactly ONE nullifier per context, so a
      second use in the same context is detectable (double-vote / Sybil defence).
    * A fresh `context` (per app / per epoch) yields an independent hash output, so
      the same human is UNLINKABLE across contexts.
    """
    return H(_TAG_NULL, system_id, context)


# ---------------------------------------------------------------------------
# Merkle tree  (the verified-human registry)
# ---------------------------------------------------------------------------
def _node(left: bytes, right: bytes) -> bytes:
    return H(_TAG_NODE, left, right)


@dataclass(frozen=True)
class AuthPathStep:
    """One step of a Merkle authentication path.

    In a REAL ZK deployment the (sibling, sibling_is_right) sequence — which encodes
    the leaf INDEX — is exactly what the STARK hides. Here it is plaintext.
    """

    sibling: bytes
    sibling_is_right: bool  # True if the sibling sits to the RIGHT of our node


class MerkleTree:
    """Fixed-shape binary Merkle tree over leaf hashes.

    Odd levels duplicate the last node (standard Bitcoin-style padding), so the
    authentication-path length is well defined.
    """

    def __init__(self, leaves: list[bytes]):
        if not leaves:
            raise ValueError("cannot build a Merkle tree with no leaves")
        self._leaves = list(leaves)
        # levels[0] = leaves, levels[-1] = [root]
        self._levels: list[list[bytes]] = [list(leaves)]
        cur = list(leaves)
        while len(cur) > 1:
            if len(cur) % 2 == 1:
                cur = cur + [cur[-1]]  # duplicate last to pad
            nxt = [_node(cur[i], cur[i + 1]) for i in range(0, len(cur), 2)]
            self._levels.append(nxt)
            cur = nxt

    @property
    def root(self) -> bytes:
        return self._levels[-1][0]

    def __len__(self) -> int:
        return len(self._leaves)

    def auth_path(self, index: int) -> list[AuthPathStep]:
        if not (0 <= index < len(self._leaves)):
            raise IndexError("leaf index out of range")
        path: list[AuthPathStep] = []
        idx = index
        for level in self._levels[:-1]:
            padded = level if len(level) % 2 == 0 else level + [level[-1]]
            if idx % 2 == 0:  # our node is on the left; sibling is on the right
                sibling = padded[idx + 1]
                path.append(AuthPathStep(sibling=sibling, sibling_is_right=True))
            else:  # our node is on the right; sibling is on the left
                sibling = padded[idx - 1]
                path.append(AuthPathStep(sibling=sibling, sibling_is_right=False))
            idx //= 2
        return path


def merkle_root_from_path(leaf: bytes, path: list[AuthPathStep]) -> bytes:
    """Recompute the root from a leaf and its authentication path.

    This is the core "membership witness" verification — the piece a real STARK
    proves in zero knowledge.
    """
    acc = leaf
    for step in path:
        if step.sibling_is_right:
            acc = _node(acc, step.sibling)
        else:
            acc = _node(step.sibling, acc)
    return acc


# ---------------------------------------------------------------------------
# Registry of verified humans
# ---------------------------------------------------------------------------
@dataclass
class Enrollment:
    """A registered verified human (issuer-side record)."""

    system_id: bytes
    level: int
    blind: bytes
    commitment: bytes
    leaf: bytes
    index: int


class VerifiedHumanRegistry:
    """Issuer/registry: holds the verified-human commitments and publishes a Merkle root.

    A real registry never learns the raw System_ID this way (it would hold blinded
    commitments issued during a verification ceremony); here we keep the openings so
    the simulation can hand out witnesses. The PUBLIC artefact is only `root`.
    """

    def __init__(self) -> None:
        self._enrollments: list[Enrollment] = []
        self._tree: MerkleTree | None = None

    def register(self, system_id: bytes, level: int, blind: bytes) -> Enrollment:
        c = commit(system_id, level, blind)
        lf = leaf_hash(c)
        e = Enrollment(
            system_id=system_id,
            level=level,
            blind=blind,
            commitment=c,
            leaf=lf,
            index=len(self._enrollments),
        )
        self._enrollments.append(e)
        self._tree = None  # invalidate cached tree
        return e

    def _build(self) -> MerkleTree:
        if self._tree is None:
            self._tree = MerkleTree([e.leaf for e in self._enrollments])
        return self._tree

    @property
    def root(self) -> bytes:
        return self._build().root

    def witness_for(self, enrollment: Enrollment) -> "MembershipWitness":
        tree = self._build()
        path = tree.auth_path(enrollment.index)
        return MembershipWitness(
            system_id=enrollment.system_id,
            level=enrollment.level,
            blind=enrollment.blind,
            leaf=enrollment.leaf,
            index=enrollment.index,
            path=path,
        )


# ---------------------------------------------------------------------------
# The proof: PublicInputs (what a STARK verifier sees) + witness (what it hides)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class MembershipWitness:
    """PRIVATE witness — in a real STARK deployment ALL of this is hidden.

    Carrying it in plaintext is exactly the gap between this model and a real ZK
    proof: `path`+`index` leak WHICH leaf, and `system_id` leaks the human.
    """

    system_id: bytes
    level: int
    blind: bytes
    leaf: bytes
    index: int
    path: list[AuthPathStep]


@dataclass(frozen=True)
class PublicInputs:
    """Exactly what a real STARK verifier would learn. Privacy tests use ONLY this."""

    root: bytes
    context: bytes
    nullifier: bytes
    required_level: int


@dataclass(frozen=True)
class PersonhoodProof:
    public: PublicInputs
    # `_witness` stands in for the opaque STARK bytes. A real verifier NEVER sees it;
    # it is present only so this simulation can re-execute the circuit.
    _witness: MembershipWitness = field(repr=False)


def prove(
    *,
    witness: MembershipWitness,
    root: bytes,
    context: bytes,
    required_level: int,
) -> PersonhoodProof:
    """Prover side. A real implementation runs a STARK prover over the circuit; here we
    just package the witness and compute the public nullifier.
    """
    null = nullifier(witness.system_id, context)
    public = PublicInputs(
        root=root,
        context=context,
        nullifier=null,
        required_level=required_level,
    )
    return PersonhoodProof(public=public, _witness=witness)


def verify_statement(proof: PersonhoodProof) -> bool:
    """Verifier side — models what the STARK verifier's constraint system checks:

      1. leaf == leaf_hash(commit(System_ID, level, blind))   (opening is consistent)
      2. merkle_root_from_path(leaf, path) == public.root      (membership)
      3. public.nullifier == H(System_ID, context)             (nullifier well-formed)
      4. level >= public.required_level                        (assurance-level binding)

    Returns True iff ALL constraints hold. In the real system the *same* four checks
    are enforced inside the ZK circuit and only the boolean verdict escapes.
    """
    w = proof._witness
    p = proof.public

    # (1) opening consistency: the leaf must be the committed (System_ID, level, blind)
    expected_leaf = leaf_hash(commit(w.system_id, w.level, w.blind))
    if expected_leaf != w.leaf:
        return False

    # (2) membership: path must reconstruct the published root
    if merkle_root_from_path(w.leaf, w.path) != p.root:
        return False

    # (3) nullifier well-formedness (binds pseudonym to the SAME secret System_ID)
    if nullifier(w.system_id, p.context) != p.nullifier:
        return False

    # (4) assurance-level binding: prove level >= required WITHOUT revealing exact level
    #     (real STARK proves the inequality; here we check it against the witness level)
    if w.level < p.required_level:
        return False

    return True


# ---------------------------------------------------------------------------
# Nullifier registry (double-use / Sybil defence per context)
# ---------------------------------------------------------------------------
class NullifierAlreadyUsed(Exception):
    pass


class NullifierRegistry:
    """Append-only set of spent nullifiers, scoped so the same (context) can't be
    reused by one human twice. A verifier calls `spend` AFTER `verify_statement`.
    """

    def __init__(self) -> None:
        self._seen: set[bytes] = set()

    def is_spent(self, null: bytes) -> bool:
        return null in self._seen

    def spend(self, null: bytes) -> None:
        if null in self._seen:
            raise NullifierAlreadyUsed(null.hex())
        self._seen.add(null)

    def accept(self, proof: PersonhoodProof) -> bool:
        """Full acceptance: statement valid AND nullifier fresh. Marks it spent."""
        if not verify_statement(proof):
            return False
        self.spend(proof.public.nullifier)  # raises on double-use
        return True


# ---------------------------------------------------------------------------
# Real-STARK cost estimate (public figures; order-of-magnitude)
# ---------------------------------------------------------------------------
STARK_COST_NOTES = """\
REAL STARK COST ESTIMATE (order-of-magnitude, from public figures)
------------------------------------------------------------------
Circuit being proven: one SHA3/Poseidon-style hash per Merkle level for a tree of
depth ~30 (10^9 humans) + one nullifier hash + a small range check for level>=req.
That is ~30-64 hash evaluations = the dominant cost.

* Proof SIZE: transparent hash-based STARKs are ~40-200 KB for circuits of this
  size (FRI proofs grow ~poly-logarithmically). Compare BBS/PS: ~1-2 KB. So the PQ
  proof is ~50-100x larger, but still fine for a network payload.
* PROVE TIME:
    - Server / laptop (multi-core, RISC-V zkVM like RISC Zero / SP1, or a
      hand-written AIR): ~0.5-5 s for a few dozen hashes. Very comfortable.
    - Phone (single/few cores, ARM, thermal + memory limits): realistically
      ~5-30 s and hundreds of MB of RAM for a general zkVM proving a hash-heavy
      circuit today. A hand-tuned native AIR with a Merkle-friendly hash
      (Poseidon2/Rescue) can push a phone toward ~1-5 s, but that is bleeding edge.
* VERIFY TIME: milliseconds either side — cheap everywhere.

FEASIBILITY READ: verification is phone-native trivially. PROVING a real STARK for
this statement is comfortably computer/home-node-native today and *borderline*
phone-native — feasible on a modern phone with a purpose-built AIR + ZK-friendly
hash, painful/slow with an off-the-shelf general zkVM. Contrast the classical
BBS/PS credential, which proves in ~1-10 ms on a phone. So the PQ hash-based path
trades phone-native proving ergonomics for post-quantum security + transparency
(no trusted setup).
"""
