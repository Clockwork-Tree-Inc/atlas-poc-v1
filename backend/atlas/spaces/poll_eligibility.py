"""Eligibility for polls/reviews — "a verified member of the right space at the right role/category
can respond anonymously." Closes the eligibility SEAM that `polls.py` leaves open (it dedups
nullifiers + checks signatures, but never verifies the voter is actually an eligible member).

Composes the existing primitives — nothing new:
  * `realid/space_pseudonym` personhood + per-scope derivation style,
  * `ledger/merkle` for the eligible-member accumulator,
  * `spaces/polls` for the ballot structure, anonymity tiers, and nullifier-dedup tally.

Model
-----
An eligible SET is a Merkle accumulator of member commitments for a (space_id, scope), where
`scope` is the role/category label (b"" = whole space; b"governor", b"healthcare", …). It's
SNAPSHOTTED at poll open — `member_set_root` + `eligible_size` (the sample size). A member commitment
`H(root, space, scope)` proves "I am a verified member of this scoped set" WITHOUT revealing which
member. The vote carries a PER-POLL nullifier `H(root, poll_id)` — one response per member per poll,
UNLINKABLE across polls (different poll_id → unrelated nullifier).

What this layer guarantees (hash-only, PoC):
  * eligible  — only a member of the snapshotted scoped set is counted (Merkle inclusion).
  * one-vote  — per-poll nullifier dedups (change-vote flips, never stacks).
  * unlinkable across polls — nullifiers don't correlate between polls.
  * sample size — eligible-set size + response count, surfaced per poll (no minimum; just the number).

Honest residual (the SAME seam `polls.py` names, made concrete): presenting the member commitment +
Merkle path lets a tallier CONFIRM eligibility, but the commitment is a stable per-(space,scope)
value — a curious tallier could link one member's ballots across polls, and a published proof could
in principle be replayed with a different nullifier. The PRODUCTION fix replaces (commitment, path)
with a ZERO-KNOWLEDGE membership proof (realid/ps_credential, zk/person_tag) that reveals ONLY the
per-poll nullifier and BINDS nullifier↔membership so it can't be replayed. This layer is the
verifiable, testable floor; the zk proof is the drop-in that removes the residual.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence, Tuple

from ..crypto.primitives import H
from ..crypto.sign import HybridSigKeypair, HybridSigPublic, sign, verify
from ..ledger import merkle
from . import polls
from .space_policy import Role, SpacePolicy

_MEMBER = b"atlas/space-member"
_POLL_NULLIFIER = b"atlas/poll-nullifier"
_MEMBER_BIND = b"atlas/space-member-bind"


def _lp(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


def member_commitment(root_secret: bytes, space_id: bytes, scope: bytes = b"") -> bytes:
    """A commitment to "root is a member of (space, scope)". Hides the root; stable per (root, space,
    scope) so one human = one membership in a scoped set; unlinkable across spaces/scopes."""
    return H(_MEMBER, _lp(root_secret), _lp(space_id), _lp(scope))


def poll_nullifier(root_secret: bytes, poll_id: bytes) -> bytes:
    """One-response-per-member-per-poll marker. Same (root, poll) → same nullifier; different poll →
    unrelated nullifier (unlinkable across polls); reveals neither the root nor which member."""
    return H(_POLL_NULLIFIER, _lp(root_secret), _lp(poll_id))


class EligibleSet:
    """A Merkle accumulator of member commitments for one (space_id, scope). Enrolled from VERIFIED
    members (each enrollment should follow a personhood check via `space_pseudonym`; the caller owns
    that gate). Snapshot `root_digest` + `size` at poll open — that's the eligible set + sample size."""

    def __init__(self, space_id: bytes, scope: bytes = b"") -> None:
        self.space_id = space_id
        self.scope = scope
        self._commitments: List[bytes] = []

    def enroll(self, root_secret: bytes) -> None:
        c = member_commitment(root_secret, self.space_id, self.scope)
        if c not in self._commitments:
            self._commitments.append(c)

    @property
    def root_digest(self) -> bytes:
        return merkle.merkle_root(self._commitments)

    @property
    def size(self) -> int:
        return len(self._commitments)

    def add_commitment(self, commitment: bytes) -> None:
        """Insert a pre-computed member commitment (used by the SpacePolicy bridge, where the space
        knows members by public key and each member self-binds their anonymous commitment)."""
        if commitment not in self._commitments:
            self._commitments.append(commitment)

    def membership_proof(self, root_secret: bytes) -> list[merkle.ProofStep]:
        c = member_commitment(root_secret, self.space_id, self.scope)
        if c not in self._commitments:
            raise KeyError("root is not an enrolled member of this scoped set")
        return merkle.inclusion_proof(self._commitments, self._commitments.index(c))


def verify_membership(commitment: bytes, proof: Sequence[merkle.ProofStep], set_root: bytes) -> bool:
    return merkle.verify_inclusion(commitment, proof, set_root)


@dataclass(frozen=True)
class EligibleBallot:
    """A `polls.PollResponse` paired with the eligibility evidence for its nullifier's owner."""
    response: polls.PollResponse
    commitment: bytes                       # member_commitment(root, space, scope) — the Merkle leaf
    membership_proof: Tuple[merkle.ProofStep, ...]


@dataclass(frozen=True)
class EligiblePoll:
    """A base poll bound to a scoped eligible set, snapshotted at open."""
    base: polls.Poll
    space_id: bytes
    scope: bytes
    member_set_root: bytes
    eligible_size: int                      # the sample size shown per poll (no minimum enforced)


@dataclass(frozen=True)
class EligiblePollResult:
    poll_id: bytes
    counts: Tuple[int, ...]
    responses: int                          # distinct eligible members who responded
    eligible_size: int                      # sample size (snapshot of the eligible set)

    def winner(self) -> int:
        return max(range(len(self.counts)), key=lambda i: self.counts[i]) if self.counts else -1


def open_poll(base: polls.Poll, eligible: EligibleSet) -> EligiblePoll:
    """Snapshot the eligible set onto a poll — captures the member-set root + sample size at open."""
    return EligiblePoll(base=base, space_id=eligible.space_id, scope=eligible.scope,
                        member_set_root=eligible.root_digest, eligible_size=eligible.size)


def mint_ballot(root_secret: bytes, poll: EligiblePoll, *, choice: int, epoch: int,
                ephemeral_kp, membership_proof: list[merkle.ProofStep]) -> EligibleBallot:
    """Client-side: derive the per-poll nullifier, cast an ANONYMOUS ballot (unlinkable to persona),
    and package the eligibility evidence. The nullifier binds to THIS poll only."""
    nul = poll_nullifier(root_secret, poll.base.poll_id())
    resp = polls.respond_anonymously(poll.base, choice=choice, nullifier=nul, epoch=epoch,
                                     ephemeral_kp=ephemeral_kp)
    commitment = member_commitment(root_secret, poll.space_id, poll.scope)
    return EligibleBallot(response=resp, commitment=commitment,
                          membership_proof=tuple(membership_proof))


def verify_ballot(poll: EligiblePoll, ballot: EligibleBallot) -> bool:
    """A ballot counts iff (a) it's a valid response for this poll AND (b) its owner is a member of
    the snapshotted eligible set."""
    return (polls.verify_response(poll.base, ballot.response)
            and verify_membership(ballot.commitment, ballot.membership_proof, poll.member_set_root))


def tally(poll: EligiblePoll, ballots: Sequence[EligibleBallot]) -> EligiblePollResult:
    """Eligibility-checked tally: keep only ballots from members of the snapshotted set, then dedup by
    per-poll nullifier (last valid response wins — a member can change their choice). Reports the
    sample size (eligible-set snapshot) alongside the response count."""
    eligible = [b.response for b in ballots if verify_ballot(poll, b)]
    result = polls.tally(poll.base, eligible)
    return EligiblePollResult(poll_id=result.poll_id, counts=result.counts,
                              responses=result.total, eligible_size=poll.eligible_size)


# --------------------------------------------------------------------------- SpacePolicy bridge
#
# A SpacePolicy knows members by PUBLIC KEY; a poll's anonymity needs a hiding, per-space commitment
# derived from the member's secret ROOT. So the member self-binds: they sign their anonymous
# `member_commitment(root, space, scope)` with the authorized key. The bridge admits a commitment
# into the eligible set iff its signer is a current member at the required role. This binds the
# anonymous commitment to a real authorized member exactly once — an outsider can't inject one.
#
# Honest note: the binding reveals (pubkey ↔ commitment) to whoever builds the set, at enroll time
# (the commitment still hides the root). Production blinds the enrollment (the set operator signs a
# BLINDED commitment), so not even the operator learns the link — same seam as the ballot layer.

def _bind_body(space_id: bytes, scope: bytes, commitment: bytes) -> bytes:
    return H(_MEMBER_BIND, _lp(space_id), _lp(scope), _lp(commitment))


@dataclass(frozen=True)
class MembershipBinding:
    """A member's signed claim binding their anonymous commitment to their authorized key."""
    pub: HybridSigPublic
    commitment: bytes
    sig: bytes


def bind_membership(root_secret: bytes, space_id: bytes, kp: HybridSigKeypair,
                    scope: bytes = b"") -> MembershipBinding:
    """Member-side: compute your per-(space, scope) commitment and sign it with your authorized key."""
    c = member_commitment(root_secret, space_id, scope)
    return MembershipBinding(pub=kp.public, commitment=c, sig=sign(kp, _bind_body(space_id, scope, c)))


def verify_binding(binding: MembershipBinding, space_id: bytes, scope: bytes) -> bool:
    return verify(binding.pub, _bind_body(space_id, scope, binding.commitment), binding.sig)


def eligible_set_from_policy(policy: SpacePolicy, *, minimum_role: Role, scope: bytes,
                             bindings: Sequence[MembershipBinding]) -> EligibleSet:
    """Build a poll's eligible set from a space's members: admit a binding's commitment iff its
    signer is a current member at >= `minimum_role` and the binding verifies. The resulting set is
    exactly "verified members of this space at this role/category", ready to open a poll over."""
    s = EligibleSet(policy.space_id, scope)
    allowed = set(policy.members_at(minimum_role))     # encoded publics
    for b in bindings:
        if b.pub.encode() in allowed and verify_binding(b, policy.space_id, scope):
            s.add_commitment(b.commitment)
    return s
