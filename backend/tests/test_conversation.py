"""Conversation state model: ordering, out-of-order, replay, persistence across
restart, and the accountable/deniable per-chat toggle."""

import os

import pytest

from atlas.keys.identity import build_identity_tree
from atlas.session.conversation import (
    Conversation,
    ConversationMode,
    Envelope,
    ReplayError,
    SignatureRejected,
    TooManySkipped,
)

CHANNEL_KEY = b"K" * 32              # static KEM channel key (who-you-are)
LK = b"L" * 32                       # live co-derived LK (what-you-say)
EPOCH = b"\x00" * 8
BEACON = b"beacon-epoch-1"
A2B, B2A = b"A->B", b"B->A"


def _pair(mode):
    """Two lockstep views of one conversation. A sends on A->B, B on B->A."""
    a_tree = build_identity_tree(os.urandom(32))
    b_tree = build_identity_tree(os.urandom(32))
    a_auth, b_auth = a_tree.child("authorship"), b_tree.child("authorship")
    common = dict(channel_key=CHANNEL_KEY, lk=LK, drand_round=EPOCH, beacon_t=BEACON)
    a = Conversation.create(mode=mode, my_direction=A2B, peer_direction=B2A,
                            authorship=a_auth, peer_public=b_auth.public, **common)
    b = Conversation.create(mode=mode, my_direction=B2A, peer_direction=A2B,
                            authorship=b_auth, peer_public=a_auth.public, **common)
    return a, b, a_auth, b_auth


@pytest.mark.parametrize("mode", [ConversationMode.ACCOUNTABLE, ConversationMode.DENIABLE])
def test_in_order_roundtrip_both_directions(mode):
    a, b, *_ = _pair(mode)
    for text in (b"hi", b"meet at 9", b"bring the ring"):
        assert b.receive(a.send(text)) == text          # A -> B
    for text in (b"on my way", b"ok"):
        assert a.receive(b.send(text)) == text           # B -> A


def test_out_of_order_delivery_opens_via_skipped_cache():
    a, b, *_ = _pair(ConversationMode.DENIABLE)
    e0, e1, e2 = a.send(b"zero"), a.send(b"one"), a.send(b"two")
    assert b.receive(e2) == b"two"                        # arrives first -> 0,1 cached as skipped
    assert b.receive(e0) == b"zero"                       # earlier ones still open
    assert b.receive(e1) == b"one"


def test_replay_is_rejected():
    a, b, *_ = _pair(ConversationMode.DENIABLE)
    e0 = a.send(b"once")
    assert b.receive(e0) == b"once"
    with pytest.raises(ReplayError):                      # same index again -> refused
        b.receive(e0)


def test_too_many_skipped_is_guarded():
    a, b, *_ = _pair(ConversationMode.DENIABLE)
    far = None
    for _ in range(300):
        far = a.send(b"x")                                # advance A far past B's next
    with pytest.raises(TooManySkipped):
        b.receive(far)


def test_persistence_across_restart_resumes_lockstep():
    a, b, a_auth, b_auth = _pair(ConversationMode.ACCOUNTABLE)
    b.receive(a.send(b"before restart 1"))
    b.receive(a.send(b"before restart 2"))
    # "app restart": serialize chain positions, drop the objects, reload with keys.
    a_blob, b_blob = a.serialize(), b.serialize()
    a2 = Conversation.deserialize(a_blob, authorship=a_auth, peer_public=b_auth.public)
    b2 = Conversation.deserialize(b_blob, authorship=b_auth, peer_public=a_auth.public)
    # resume exactly where they left off, still in lockstep and still verifying.
    assert b2.receive(a2.send(b"after restart")) == b"after restart"
    assert a2.receive(b2.send(b"reply after restart")) == b"reply after restart"


def test_forward_secrecy_consumed_key_is_gone_after_restart():
    a, b, a_auth, b_auth = _pair(ConversationMode.ACCOUNTABLE)
    e0 = a.send(b"secret zero")
    b.receive(e0)                                         # consume index 0
    # persist AFTER consuming: the restored state must not be able to reopen index 0.
    b2 = Conversation.deserialize(b.serialize(), authorship=b_auth, peer_public=a_auth.public)
    with pytest.raises(ReplayError):                      # consumed key discarded -> unrecoverable
        b2.receive(e0)


def test_accountable_valid_signature_verifies():
    a, b, *_ = _pair(ConversationMode.ACCOUNTABLE)
    assert b.receive(a.send(b"I authorize the transfer")) == b"I authorize the transfer"


def test_accountable_tampered_signature_is_rejected():
    """A forged/corrupted authorship signature fails closed — the message is
    refused even though the (symmetric) ciphertext would open."""
    a, b, *_ = _pair(ConversationMode.ACCOUNTABLE)
    env = a.send(b"I authorize the transfer")
    env.signature = env.signature[:-1] + bytes([env.signature[-1] ^ 1])
    with pytest.raises(SignatureRejected):
        b.receive(env)


def test_accountable_wrong_author_key_is_rejected():
    """B verifying against the WRONG peer public (a stranger's) rejects a genuine
    signature — the signature binds THIS author, non-repudiably."""
    a, _, a_auth, _ = _pair(ConversationMode.ACCOUNTABLE)
    stranger = build_identity_tree(os.urandom(32)).child("authorship")
    b_wrong = Conversation.create(mode=ConversationMode.ACCOUNTABLE, my_direction=B2A,
                                  peer_direction=A2B, channel_key=CHANNEL_KEY, lk=LK,
                                  drand_round=EPOCH, beacon_t=BEACON,
                                  authorship=build_identity_tree(os.urandom(32)).child("authorship"),
                                  peer_public=stranger.public)   # not A's real key
    with pytest.raises(SignatureRejected):
        b_wrong.receive(a.send(b"genuine but attributed to the wrong key"))


def test_deniable_carries_no_signature_and_is_symmetric():
    a, b, *_ = _pair(ConversationMode.DENIABLE)
    env = a.send(b"off the record")
    assert env.signature == b""                          # nothing binds authorship -> deniable
    assert b.receive(env) == b"off the record"           # opens on the shared chain alone


def test_wrong_channel_key_cannot_open():
    a, _, a_auth, b_auth = _pair(ConversationMode.DENIABLE)
    # B derives its chains from a DIFFERENT channel key -> seeds diverge.
    b_bad = Conversation.create(mode=ConversationMode.DENIABLE, my_direction=B2A, peer_direction=A2B,
                                channel_key=b"X" * 32, lk=LK, drand_round=EPOCH, beacon_t=BEACON)
    with pytest.raises(Exception):
        b_bad.receive(a.send(b"secret"))


def test_envelope_wire_roundtrip():
    a, b, *_ = _pair(ConversationMode.ACCOUNTABLE)
    env = a.send(b"over the relay")
    rewired = Envelope.from_wire(env.to_wire())
    assert b.receive(rewired) == b"over the relay"
