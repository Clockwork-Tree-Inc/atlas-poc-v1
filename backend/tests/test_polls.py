"""Polls — Sybil-free, one-human-one-response, at three anonymity levels."""

import pytest

from atlas.crypto.sign import keypair_from_seed
from atlas.spaces.polls import (
    IdentityTier, create_poll, respond, respond_anonymously, tally, verify_poll, verify_response,
)


def kp(n):
    return keypair_from_seed(bytes([n]) * 32)


OPTS = [b"yes", b"no", b"maybe"]


def _poll(tier=IdentityTier.VERIFIED_PERSON):
    return create_poll(kp(1), question=b"ship it?", options=OPTS, tier=tier, epoch=1)


# --------------------------------------------------------------------------- poll object
def test_create_and_verify_poll():
    p = _poll()
    assert verify_poll(p) is True
    p.question = b"tampered"
    assert verify_poll(p) is False


def test_poll_needs_two_options():
    with pytest.raises(ValueError):
        create_poll(kp(1), question=b"q", options=[b"only"], tier=IdentityTier.PSEUDONYMOUS, epoch=1)


# --------------------------------------------------------------------------- tally + one-human-one-vote
def test_pseudonymous_tally():
    p = _poll(IdentityTier.PSEUDONYMOUS)
    rs = [
        respond(kp(2), p, choice=0, nullifier=b"h2", epoch=1),   # yes
        respond(kp(3), p, choice=0, nullifier=b"h3", epoch=1),   # yes
        respond(kp(4), p, choice=1, nullifier=b"h4", epoch=1),   # no
    ]
    res = tally(p, rs)
    assert res.counts == (2, 1, 0)
    assert res.total == 3
    assert res.winner() == 0


def test_one_human_one_response_last_wins():
    p = _poll()
    rs = [
        respond(kp(2), p, choice=0, nullifier=b"human-A", epoch=1),   # yes
        respond(kp(2), p, choice=1, nullifier=b"human-A", epoch=2),   # changed to no
    ]
    res = tally(p, rs)
    assert res.counts == (0, 1, 0)                                     # only the later ballot counts
    assert res.total == 1


def test_sybil_across_personas_deduped_by_nullifier():
    p = _poll()
    # one human, three different personas, SAME per-human nullifier -> counts once
    rs = [respond(kp(n), p, choice=0, nullifier=b"one-human", epoch=1) for n in (2, 3, 4)]
    res = tally(p, rs)
    assert res.total == 1 and res.counts == (1, 0, 0)


# --------------------------------------------------------------------------- anonymity
def test_anonymous_ballot_is_unlinkable_but_counts():
    p = _poll(IdentityTier.ANONYMOUS)
    voter = kp(2)                         # the real human's persona
    eph = kp(200)                         # a fresh ephemeral ballot key, unlinkable to `voter`
    r = respond_anonymously(p, choice=2, nullifier=b"h2", epoch=1, ephemeral_kp=eph)
    # the ballot reveals the EPHEMERAL key, never the voter's persona
    assert r.ballot_key.encode() != voter.public.encode()
    assert r.ballot_key.encode() == eph.public.encode()
    assert verify_response(p, r) is True
    res = tally(p, [r])
    assert res.counts == (0, 0, 1)        # tallied, still Sybil-gated by the nullifier


def test_anonymous_still_one_human_one_response():
    p = _poll(IdentityTier.ANONYMOUS)
    # same human (same nullifier) submits two anonymous ballots via different ephemeral keys -> once
    r1 = respond_anonymously(p, choice=0, nullifier=b"human-X", epoch=1, ephemeral_kp=kp(201))
    r2 = respond_anonymously(p, choice=1, nullifier=b"human-X", epoch=2, ephemeral_kp=kp(202))
    res = tally(p, [r1, r2])
    assert res.total == 1 and res.counts == (0, 1, 0)                  # last wins, no stuffing


# --------------------------------------------------------------------------- rejection
def test_choice_out_of_range_rejected():
    p = _poll()
    with pytest.raises(ValueError):
        respond(kp(2), p, choice=9, nullifier=b"h2", epoch=1)


def test_tampered_response_rejected():
    p = _poll()
    r = respond(kp(2), p, choice=0, nullifier=b"h2", epoch=1)
    r.choice = 1                                                       # tamper after signing
    assert verify_response(p, r) is False
    assert tally(p, [r]).total == 0


def test_response_for_other_poll_ignored():
    p = _poll()
    other = create_poll(kp(9), question=b"other", options=OPTS, tier=IdentityTier.PSEUDONYMOUS, epoch=1)
    r = respond(kp(2), other, choice=0, nullifier=b"h2", epoch=1)
    assert tally(p, [r]).total == 0                                   # wrong poll_id -> dropped
