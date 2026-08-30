"""Social layer — like/dislike votes (one-human-one-vote), threaded comments, and reports."""

import pytest

from atlas.authority import fs_keygen
from atlas.crypto.sign import keypair_from_seed
from atlas.spaces.content import SpaceStore, content_commitment
from atlas.spaces.kinds import make_space, invite, SpaceKind, Role
from atlas.spaces.social import (
    DISLIKE, LIKE, cast_vote, file_report, report_counts, tally, verify_report, verify_vote,
)

SID = b"space-1"


def kp(n):
    return keypair_from_seed(bytes([n]) * 32)


def _owner():
    return fs_keygen(bytes(range(32)), height=3)


POST = b"post-hash-1"


# --------------------------------------------------------------------------- votes
def test_like_and_dislike_tally():
    votes = [
        cast_vote(kp(1), target=POST, value=LIKE, nullifier=b"h1", epoch=1),
        cast_vote(kp(2), target=POST, value=LIKE, nullifier=b"h2", epoch=1),
        cast_vote(kp(3), target=POST, value=DISLIKE, nullifier=b"h3", epoch=1),
    ]
    s = tally(POST, votes)
    assert (s.likes, s.dislikes, s.net) == (2, 1, 1)


def test_one_human_one_vote_last_wins():
    # Same human (same nullifier) votes twice — the LAST cast wins, no stacking.
    votes = [
        cast_vote(kp(1), target=POST, value=LIKE, nullifier=b"human-A", epoch=1),
        cast_vote(kp(1), target=POST, value=DISLIKE, nullifier=b"human-A", epoch=2),  # changed mind
    ]
    s = tally(POST, votes)
    assert (s.likes, s.dislikes) == (0, 1)


def test_sybil_across_personas_is_deduped_by_nullifier():
    # One human voting from THREE different personas but the SAME nullifier counts ONCE.
    votes = [cast_vote(kp(n), target=POST, value=LIKE, nullifier=b"one-human", epoch=1)
             for n in (1, 2, 3)]
    s = tally(POST, votes)
    assert s.likes == 1


def test_vote_only_counts_for_its_target():
    votes = [cast_vote(kp(1), target=b"other", value=LIKE, nullifier=b"h1", epoch=1)]
    assert tally(POST, votes).likes == 0


def test_tampered_vote_rejected():
    v = cast_vote(kp(1), target=POST, value=LIKE, nullifier=b"h1", epoch=1)
    v.value = DISLIKE                                    # tamper after signing
    assert verify_vote(v) is False
    assert tally(POST, [v]).dislikes == 0


def test_invalid_vote_value_rejected():
    with pytest.raises(ValueError):
        cast_vote(kp(1), target=POST, value=5, nullifier=b"h1", epoch=1)


# --------------------------------------------------------------------------- threaded comments
def test_comment_threads_under_parent():
    pub, signer = _owner()
    space = make_space(SID, SpaceKind.FRIENDS, pub)      # INVITE / member-gated
    store = SpaceStore(space)
    A = kp(2)
    chain = [invite(space, signer, invitee=A.public, role=Role.MEMBER)]
    post = store.post(chain, author=b"aun", content=b"hello", now=100)
    reply = store.post(chain, author=b"aun", content=b"nice", now=101, parent=post.content_hash)
    assert reply.parent == post.content_hash
    assert reply.content_hash == content_commitment(SID, b"aun", b"nice", post.content_hash)
    assert store.replies(post.content_hash) == [reply]
    assert store.replies(b"nobody") == []


# --------------------------------------------------------------------------- reports
def test_file_and_verify_report():
    r = file_report(kp(1), target=POST, reason=b"spam".decode(), epoch=1)
    assert verify_report(r) is True
    r.reason = "harm"                                    # tamper after signing
    assert verify_report(r) is False


def test_report_counts_dedupe_same_reporter():
    reports = [
        file_report(kp(1), target=POST, reason="spam", epoch=1),
        file_report(kp(1), target=POST, reason="spam", epoch=2),   # same reporter, no pile-on
        file_report(kp(2), target=POST, reason="abuse", epoch=1),
    ]
    assert report_counts(reports)[POST] == 2             # two DISTINCT reporters


def test_report_is_not_a_veto():
    # A report records a flag but removes nothing on its own — moderation is a separate MODERATOR act.
    r = file_report(kp(1), target=POST, reason="spam", epoch=1)
    assert verify_report(r) and report_counts([r]) == {POST: 1}
