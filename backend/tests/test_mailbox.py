"""Rotating mailboxes + sealed sender (metadata hardening #25): the relay must not be able to
reconstruct the social graph. It sees rotating unlinkable addresses and opaque blobs — no stable
handle, no sender, no recipient identity. Established contacts rotate per epoch; cold contact goes
through an opt-in public inbox and then moves to rotating mailboxes."""

import pytest

from atlas.net.privacy.mailbox import (
    MAILBOX_BYTES,
    MailboxEndpoint,
    MailboxError,
    MailboxRelay,
    SealedEnvelope,
    catch_up_epochs,
    derive_mailbox,
    epoch_for_round,
    open_message,
    public_inbox_id,
    seal_first_contact,
    seal_message,
)

A = b"persona-A"
B = b"persona-B"
SECRET = b"\x5a" * 32
E1 = b"\x00\x00\x00\x01"
E2 = b"\x00\x00\x00\x02"


def test_both_endpoints_derive_the_same_mailbox():
    # A sending to B, and B computing its inbound-from-A, land on the same id (same call).
    out = derive_mailbox(SECRET, sender=A, recipient=B, epoch=E1)
    inbound = derive_mailbox(SECRET, sender=A, recipient=B, epoch=E1)
    assert out == inbound and len(out) == MAILBOX_BYTES


def test_mailbox_rotates_and_is_unlinkable_across_epochs():
    m1 = derive_mailbox(SECRET, sender=A, recipient=B, epoch=E1)
    m2 = derive_mailbox(SECRET, sender=A, recipient=B, epoch=E2)
    assert m1 != m2                                   # rotates every epoch
    # Without the secret the two ids share nothing linkable (independent PRF outputs).
    assert not (m1[:4] == m2[:4])


def test_direction_separates_inbound_from_outbound():
    a_to_b = derive_mailbox(SECRET, sender=A, recipient=B, epoch=E1)
    b_to_a = derive_mailbox(SECRET, sender=B, recipient=A, epoch=E1)
    assert a_to_b != b_to_a                           # A->B and B->A never collide


def test_different_pairs_do_not_collide():
    other = b"\xa1" * 32
    assert derive_mailbox(SECRET, sender=A, recipient=B, epoch=E1) != \
        derive_mailbox(other, sender=A, recipient=B, epoch=E1)


def test_sealed_sender_roundtrip_and_relay_sees_no_identity():
    env = seal_message(SECRET, sender=A, recipient=B, epoch=E1, seq=7, plaintext=b"hello B")
    # The relay's whole view is (mailbox, blob) — assert neither carries a party id in the clear.
    assert A not in env.blob and B not in env.blob and A not in env.mailbox and B not in env.mailbox
    sender, seq, pt = open_message(SECRET, env, epoch=E1)
    assert (sender, seq, pt) == (A, 7, b"hello B")


def test_wrong_secret_or_epoch_opens_to_none():
    env = seal_message(SECRET, sender=A, recipient=B, epoch=E1, seq=1, plaintext=b"x")
    assert open_message(b"\x00" * 32, env, epoch=E1) is None      # not my conversation
    assert open_message(SECRET, env, epoch=E2) is None            # stale/replayed to another epoch


def test_mailbox_bound_as_aad_blocks_readdress_replay():
    env = seal_message(SECRET, sender=A, recipient=B, epoch=E1, seq=1, plaintext=b"x")
    moved = SealedEnvelope(mailbox=b"\x99" * MAILBOX_BYTES, blob=env.blob)
    assert open_message(SECRET, moved, epoch=E1) is None          # blob re-addressed -> aad fails


def test_endpoint_send_receive_through_relay():
    relay = MailboxRelay()
    a = MailboxEndpoint(A, relay=relay)
    b = MailboxEndpoint(B, relay=relay)
    a.add_contact(B, SECRET)
    b.add_contact(A, SECRET)
    # No registration/enrollment: B never told the relay it was listening. Delivery + polling
    # alone route the message — the box springs into existence on delivery.
    a.send(B, b"first", epoch=E1)
    a.send(B, b"second", epoch=E1)
    got = b.receive(A, epoch=E1)
    assert got == [(1, b"first"), (2, b"second")]
    # Next epoch: different mailbox, nothing leaks backwards.
    assert b.receive(A, epoch=E2) == []


def test_beacon_epoch_and_catch_up_window_shape():
    assert epoch_for_round(1) == epoch_for_round(1) and epoch_for_round(1) != epoch_for_round(2)
    assert len(epoch_for_round(102)) == 8                              # 8-byte big-endian round index
    # newest-first, inclusive both ends
    assert catch_up_epochs(102, window=2) == [epoch_for_round(r) for r in (102, 101, 100)]
    # clamps at round 0 (no negative rounds)
    assert catch_up_epochs(1, window=5) == [epoch_for_round(1), epoch_for_round(0)]
    with pytest.raises(MailboxError):
        catch_up_epochs(10, window=-1)


def test_single_epoch_receive_misses_earlier_epochs():
    """Baseline: polling only the newest epoch gets only that epoch's message (the gap #43 fixes)."""
    relay = MailboxRelay()
    a = MailboxEndpoint(A, relay=relay); b = MailboxEndpoint(B, relay=relay)
    a.add_contact(B, SECRET); b.add_contact(A, SECRET)
    a.send_at_round(B, b"r100", now_round=100)
    a.send_at_round(B, b"r102", now_round=102)
    assert b.receive(A, epoch=epoch_for_round(102)) == [(2, b"r102")]  # r100 missed


def test_offline_recipient_catches_up_across_epochs():
    """B is offline while A sends across several beacon rounds; a windowed receive gets them all."""
    relay = MailboxRelay()
    a = MailboxEndpoint(A, relay=relay); b = MailboxEndpoint(B, relay=relay)
    a.add_contact(B, SECRET); b.add_contact(A, SECRET)
    a.send_at_round(B, b"r100", now_round=100)
    a.send_at_round(B, b"r101", now_round=101)
    a.send_at_round(B, b"r102", now_round=102)
    # B was offline; comes online at 102 and polls a window back — gets all three
    got = b.receive_window(A, now_round=102, window=5)
    assert sorted(pt for _seq, pt in got) == [b"r100", b"r101", b"r102"]


def test_catch_up_tolerates_sender_receiver_clock_skew():
    relay = MailboxRelay()
    a = MailboxEndpoint(A, relay=relay); b = MailboxEndpoint(B, relay=relay)
    a.add_contact(B, SECRET); b.add_contact(A, SECRET)
    a.send_at_round(B, b"skewed", now_round=100)          # sender's clock says 100
    # receiver's clock is +2 (102); a window of 5 still covers round 100
    assert [pt for _s, pt in b.receive_window(A, now_round=102, window=5)] == [b"skewed"]
    # but a message older than the window is (correctly) not caught
    a.send_at_round(B, b"too-old", now_round=90)
    assert b"too-old" not in [pt for _s, pt in b.receive_window(A, now_round=102, window=5)]


def test_relay_state_holds_no_graph():
    relay = MailboxRelay()
    a = MailboxEndpoint(A, relay=relay)
    a.add_contact(B, SECRET)
    a.send(B, b"hi", epoch=E1)
    # Everything the relay stores is keyed by a rotating id; no persona id appears anywhere.
    blob = b"".join(k + b"".join(v) for k, v in relay._boxes.items())
    assert A not in blob and B not in blob


def test_no_directory_relay_has_no_register_and_learns_boxes_only_on_use():
    relay = MailboxRelay()
    # There is no enrollment surface to leak a listener set.
    assert not hasattr(relay, "register")
    # A relay that no one has used sees nothing — no directory of who exists.
    assert relay._boxes == {}
    # A box exists to the relay ONLY after a blob is delivered to it (never pre-declared).
    env = seal_message(SECRET, sender=A, recipient=B, epoch=E1, seq=1, plaintext=b"hi")
    relay.deliver(env)
    assert list(relay._boxes.keys()) == [env.mailbox]
    relay.fetch(env.mailbox)
    assert relay._boxes == {}                          # and vanishes on fetch


def test_public_inbox_is_stable_and_cold_contact_delivers():
    pub = b"B-published-key"
    box = public_inbox_id(pub)
    assert box == public_inbox_id(pub)                 # stable (findable), unlike rotating boxes
    # Cold sender seals to the published key (asymmetric seal injected; xor stub for the test).
    key = b"k" * 8

    def seal_to_pub(m: bytes) -> bytes:
        return bytes(c ^ key[i % len(key)] for i, c in enumerate(m))

    relay = MailboxRelay()
    env = seal_first_contact(pub, sender=A, plaintext=b"can we connect?", seal_to_pub=seal_to_pub)
    assert env.mailbox == box and A not in env.blob    # sender sealed inside, not in the clear
    relay.deliver(env)
    assert relay.fetch(box) == [env.blob]              # lands in B's public inbox
