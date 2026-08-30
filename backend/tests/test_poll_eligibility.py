"""Anonymous-eligible polls: only verified members of the right scoped space respond, one vote each,
unlinkable across polls, with the sample size shown per poll."""
import pytest

from atlas.crypto.sign import keypair_from_seed
from atlas.spaces import polls
from atlas.spaces import poll_eligibility as pe

SPACE = b"space:acme"
OPTS = [b"yes", b"no", b"maybe"]


def kp(n):
    return keypair_from_seed(bytes([n]) * 32)


def root(n):
    return bytes([n]) * 32


def _base_poll():
    return polls.create_poll(kp(1), question=b"ship it?", options=OPTS,
                             tier=polls.IdentityTier.ANONYMOUS, epoch=1)


def _set_with(members, space_id=SPACE, scope=b""):
    s = pe.EligibleSet(space_id, scope)
    for m in members:
        s.enroll(m)
    return s


def test_eligible_member_counts_and_sample_size_shown():
    members = [root(10), root(11), root(12)]
    s = _set_with(members)
    poll = pe.open_poll(_base_poll(), s)
    assert poll.eligible_size == 3            # sample size snapshotted at open

    ballots = []
    for i, m in enumerate(members):
        ballots.append(pe.mint_ballot(m, poll, choice=i % 3, epoch=1,
                                      ephemeral_kp=kp(100 + i),
                                      membership_proof=s.membership_proof(m)))
    res = pe.tally(poll, ballots)
    assert res.responses == 3
    assert res.eligible_size == 3
    assert sum(res.counts) == 3


def test_non_member_ballot_is_excluded():
    s = _set_with([root(10), root(11)])
    poll = pe.open_poll(_base_poll(), s)

    # An outsider forges a ballot with a self-made commitment + empty proof — not in the set.
    outsider = root(99)
    nul = pe.poll_nullifier(outsider, poll.base.poll_id())
    resp = polls.respond_anonymously(poll.base, choice=0, nullifier=nul, epoch=1, ephemeral_kp=kp(199))
    forged = pe.EligibleBallot(response=resp,
                               commitment=pe.member_commitment(outsider, SPACE, b""),
                               membership_proof=())
    assert pe.verify_ballot(poll, forged) is False
    res = pe.tally(poll, [forged])
    assert res.responses == 0                 # excluded — not an eligible member


def test_one_vote_per_member_change_flips_not_stacks():
    m = root(10)
    s = _set_with([m, root(11)])
    poll = pe.open_poll(_base_poll(), s)
    proof = s.membership_proof(m)

    b1 = pe.mint_ballot(m, poll, choice=0, epoch=1, ephemeral_kp=kp(100), membership_proof=proof)
    b2 = pe.mint_ballot(m, poll, choice=1, epoch=2, ephemeral_kp=kp(101), membership_proof=proof)
    res = pe.tally(poll, [b1, b2])
    assert res.responses == 1                 # same per-poll nullifier -> deduped
    assert res.counts[1] == 1 and res.counts[0] == 0   # last valid response wins


def test_nullifiers_unlinkable_across_polls():
    m = root(10)
    s = _set_with([m, root(11)])
    p1 = pe.open_poll(polls.create_poll(kp(1), question=b"q1", options=OPTS,
                                        tier=polls.IdentityTier.ANONYMOUS, epoch=1), s)
    p2 = pe.open_poll(polls.create_poll(kp(1), question=b"q2", options=OPTS,
                                        tier=polls.IdentityTier.ANONYMOUS, epoch=2), s)
    n1 = pe.poll_nullifier(m, p1.base.poll_id())
    n2 = pe.poll_nullifier(m, p2.base.poll_id())
    assert n1 != n2                           # same human, different polls -> unrelated markers


def test_scope_gates_eligibility_by_role_category():
    gov, worker = root(10), root(11)
    governors = _set_with([gov], scope=b"governor")     # a poll open only to governors
    poll = pe.open_poll(_base_poll(), governors)
    assert poll.eligible_size == 1

    # The governor can prove membership; a non-governor worker cannot (not in the scoped set).
    ok = pe.mint_ballot(gov, poll, choice=0, epoch=1, ephemeral_kp=kp(100),
                        membership_proof=governors.membership_proof(gov))
    assert pe.verify_ballot(poll, ok) is True
    with pytest.raises(KeyError):
        governors.membership_proof(worker)


def test_wrong_space_or_scope_commitment_does_not_verify():
    m = root(10)
    s = _set_with([m], space_id=SPACE, scope=b"governor")
    poll = pe.open_poll(_base_poll(), s)
    proof = s.membership_proof(m)
    # A commitment for a DIFFERENT scope won't match the leaf the proof authenticates.
    wrong = pe.member_commitment(m, SPACE, b"")   # scope="" vs the set's "governor"
    assert pe.verify_membership(wrong, proof, poll.member_set_root) is False


# --------------------------------------------------------------------------- SpacePolicy bridge
from atlas.spaces.space_policy import Role, SpacePolicy


def _policy_with(creator, grants):
    p = SpacePolicy.genesis(b"space:acme", creator.public)
    from atlas.crypto.sign import sign
    for who, role, ep in grants:
        ch = p.propose("grant", target=who.public, role=role, epoch=ep)
        p.authorize(ch, [(creator.public, sign(creator, ch.body()))])
    return p


def test_eligible_set_from_policy_admits_only_authorized_members():
    creator, worker, outsider = kp(1), kp(2), kp(9)
    p = _policy_with(creator, [(worker, Role.CONTRIBUTOR, 1)])

    # creator + worker bind (roots are their own secrets); the outsider is NOT in the policy.
    b_creator = pe.bind_membership(root(1), p.space_id, creator, scope=b"")
    b_worker = pe.bind_membership(root(2), p.space_id, worker, scope=b"")
    b_outsider = pe.bind_membership(root(9), p.space_id, outsider, scope=b"")

    s = pe.eligible_set_from_policy(p, minimum_role=Role.CONTRIBUTOR, scope=b"",
                                    bindings=[b_creator, b_worker, b_outsider])
    assert s.size == 2                     # creator (governor>=contributor) + worker; outsider excluded

    poll = pe.open_poll(_base_poll(), s)
    ballot = pe.mint_ballot(root(2), poll, choice=1, epoch=1, ephemeral_kp=kp(102),
                            membership_proof=s.membership_proof(root(2)))
    assert pe.verify_ballot(poll, ballot)
    assert pe.tally(poll, [ballot]).eligible_size == 2


def test_bridge_respects_role_scoping():
    creator, worker = kp(1), kp(2)
    p = _policy_with(creator, [(worker, Role.CONTRIBUTOR, 1)])
    b_creator = pe.bind_membership(root(1), p.space_id, creator)
    b_worker = pe.bind_membership(root(2), p.space_id, worker)
    # a GOVERNOR-only poll: only the creator qualifies
    gov_only = pe.eligible_set_from_policy(p, minimum_role=Role.GOVERNOR, scope=b"",
                                           bindings=[b_creator, b_worker])
    assert gov_only.size == 1


def test_forged_binding_is_rejected():
    creator, worker = kp(1), kp(2)
    p = _policy_with(creator, [(worker, Role.CONTRIBUTOR, 1)])
    # worker's pubkey but a commitment they didn't sign (creator's commitment) -> binding fails
    bad = pe.MembershipBinding(pub=worker.public,
                               commitment=pe.member_commitment(root(1), p.space_id, b""),
                               sig=pe.bind_membership(root(2), p.space_id, worker).sig)
    assert pe.verify_binding(bad, p.space_id, b"") is False
    s = pe.eligible_set_from_policy(p, minimum_role=Role.CONTRIBUTOR, scope=b"", bindings=[bad])
    assert s.size == 0
