"""Governed index: certified non-profits vote the col/value index; median + quorum make it robust
and Sybil-free, and it feeds the issuance engine."""
import pytest

from atlas.economy import (
    EconomyState,
    IndexGovernance,
    IndexVote,
    PoLEPool,
    QuorumError,
    collect_pole,
    issue,
)


def _gov(n=5, quorum=3):
    g = IndexGovernance(quorum=quorum)
    for i in range(n):
        g.certify(f"np:{i}")
    return g


def test_only_certified_votes_count_and_quorum_enforced():
    g = _gov(n=2, quorum=3)
    votes = [IndexVote(f"np:{i}", 1, 100, 10_000) for i in range(2)]
    votes.append(IndexVote("np:imposter", 1, 999, 999))   # not certified -> ignored
    with pytest.raises(QuorumError):
        g.ratify(votes, epoch=1)


def test_one_vote_per_certified_body_last_wins():
    g = _gov(n=3, quorum=3)
    votes = [
        IndexVote("np:0", 1, 100, 10_000),
        IndexVote("np:0", 1, 500, 10_000),   # same body re-votes -> replaces, no double count
        IndexVote("np:1", 1, 100, 10_000),
        IndexVote("np:2", 1, 100, 10_000),
    ]
    col, value = g.ratify(votes, epoch=1)
    assert col == 100 and value == 10_000     # np:0's later 500 is one vote; median of {500,100,100}=100


def test_median_is_robust_to_a_captured_or_mistaken_voter():
    g = _gov(n=5, quorum=3)
    votes = [IndexVote(f"np:{i}", 1, 100, 10_000) for i in range(4)]
    votes.append(IndexVote("np:4", 1, 9_999_999, 1))      # one wildly manipulated vote
    col, value = g.ratify(votes, epoch=1)
    assert col == 100 and value == 10_000                 # median ignores the outlier


def test_ratified_index_feeds_the_issuance_engine():
    g = _gov(n=3, quorum=3)
    votes = [IndexVote(f"np:{i}", 7, 120, 8_000) for i in range(3)]  # COL 120, token below par
    col, value = g.ratify(votes, epoch=7)
    pool = PoLEPool()
    for i in range(4):
        pool.add(collect_pole(f"p{i}".encode(), 7, b"e", live=True))
    r = issue(pool, col_index=col, value_index=value, state=EconomyState(supply=1_000_000))
    # UBI reflects the voted COL, denominated at the voted (below-par) value
    assert r.ubi_per_person == col * 10_000 // value
    assert "value_below_par" in r.controls
