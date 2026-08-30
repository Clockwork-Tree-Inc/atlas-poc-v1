"""Group conversation crypto: starter key + member-add/remove rekey + continuous ratchet
(no-history-on-join, no-future-on-remove, per-message forward secrecy); optional commitment ledger;
person-scoped block."""

import os

import pytest

from atlas.crypto import kem
from atlas.session.group_ratchet import (BlockList, ConversationLedger, GroupController,
                                         GroupMember, GroupSession, message_key)
from atlas.session.tunnel import Message, SendMode, open_message, seal


def _member(name: bytes) -> GroupMember:
    return GroupMember(handle=name, kem=kem.generate_keypair())


def _session(m: GroupMember) -> GroupSession:
    return GroupSession(me=m.handle, kem=m.kem)


def test_starter_key_shared_and_messages_flow_within_epoch():
    A, B = _member(b"A"), _member(b"B")
    ctrl = GroupController([A, B])
    c0 = ctrl.create()
    sA, sB = _session(A), _session(B)
    assert sA.apply(c0) and sB.apply(c0)
    assert sA.epoch_secret == sB.epoch_secret           # starter established one shared group key
    # A sends message #0; B derives the same per-message key and reads it
    ct = seal(b"hi from A", mode=SendMode.NORMAL, key=message_key(sA.epoch_secret, 0)).ciphertext
    assert open_message(Message(mode=SendMode.NORMAL, ciphertext=ct), key=message_key(sB.epoch_secret, 0)) == b"hi from A"
    # per-message forward secrecy: message #1 uses a different key
    assert message_key(sA.epoch_secret, 0) != message_key(sA.epoch_secret, 1)


def test_added_member_cannot_read_history():
    A, B, C = _member(b"A"), _member(b"B"), _member(b"C")
    ctrl = GroupController([A, B])
    c0 = ctrl.create()
    sA = _session(A); sA.apply(c0)
    epoch0_secret = sA.epoch_secret
    ct0 = seal(b"pre-join secret", mode=SendMode.NORMAL, key=message_key(epoch0_secret, 0)).ciphertext

    c1 = ctrl.add(C)                                    # rekey to epoch 1, C joins
    sC = _session(C)
    assert not sC.apply(c0)                             # C was not in epoch 0 -> cannot open that commit
    assert sC.apply(c1)                                 # C joins at epoch 1
    assert sC.epoch_secret != epoch0_secret             # C never gets the epoch-0 secret
    # C cannot read the pre-join message: its epoch-1 key doesn't open the epoch-0 ciphertext
    with pytest.raises(Exception):
        open_message(Message(mode=SendMode.NORMAL, ciphertext=ct0), key=message_key(sC.epoch_secret, 0))


def test_removed_member_cannot_read_future():
    A, B = _member(b"A"), _member(b"B")
    ctrl = GroupController([A, B])
    sA, sB = _session(A), _session(B)
    sA.apply(ctrl.create()); sB.apply(ctrl.create())

    c_rm = ctrl.remove(B.handle)                        # rekey to a FRESH epoch, B excluded
    assert sA.apply(c_rm)                               # A follows
    assert not sB.apply(c_rm)                           # B is not in the seals -> cannot get the new secret
    post_removal = seal(b"after B left", mode=SendMode.NORMAL, key=message_key(sA.epoch_secret, 0)).ciphertext
    # B still holds its OLD epoch secret, but the new secret is fresh (not derived from it) -> B's
    # stale key cannot open post-removal traffic
    assert sB.epoch_secret != sA.epoch_secret
    with pytest.raises(Exception):
        open_message(Message(mode=SendMode.NORMAL, ciphertext=post_removal), key=message_key(sB.epoch_secret, 0))


def test_rekey_self_heals_a_compromised_epoch_no_membership_change():
    """Post-compromise security: after a presence-driven rekey, a snapshot of the OLD epoch secret
    can no longer read new traffic — and no member was added or removed."""
    A, B = _member(b"A"), _member(b"B")
    ctrl = GroupController([A, B])
    sA, sB = _session(A), _session(B)
    sA.apply(ctrl.create()); sB.apply(ctrl.create())
    stolen = sA.epoch_secret                              # attacker snapshots the current epoch secret
    members_before = list(sA.members)

    # a live-presence epoch fires -> heal. clean QRNG-seam value gates in as presence entropy.
    c_heal = ctrl.rekey(presence_entropy=os.urandom(32))
    assert sA.apply(c_heal) and sB.apply(c_heal)          # both current members advance in lockstep
    assert sA.epoch_secret == sB.epoch_secret             # ...to the SAME new secret
    assert sA.epoch_secret != stolen                      # which is independent of the stolen one
    assert sA.members == members_before                   # NO membership change — pure heal

    healed = seal(b"post-heal", mode=SendMode.NORMAL, key=message_key(sA.epoch_secret, 0)).ciphertext
    assert open_message(Message(mode=SendMode.NORMAL, ciphertext=healed),
                        key=message_key(sB.epoch_secret, 0)) == b"post-heal"
    # the attacker's stolen (old) secret is now useless against post-heal traffic
    with pytest.raises(Exception):
        open_message(Message(mode=SendMode.NORMAL, ciphertext=healed), key=message_key(stolen, 0))


def test_optional_ledger_is_commitments_not_content_and_tamper_evident():
    led = ConversationLedger()
    e0 = led.record(b"first message")
    led.record(b"second message")
    assert led.verify_chain()
    assert e0.commitment != b"first message"            # a fingerprint, not the content
    # tamper: rewrite an entry's commitment -> chain no longer verifies
    led.entries[0].commitment = os.urandom(32)
    assert not led.verify_chain()


def test_person_block_binds_the_person_not_the_pseudonym():
    scope = b"conversation-42"
    bl = BlockList(scope)
    person = os.urandom(32)          # a person's root secret (shared by all their pseudonyms)
    bl.block(person)
    assert bl.is_blocked(person)     # blocked person stays blocked...
    # ...even though a "new pseudonym" is just the same person_root in this scope -> same tag
    assert bl.person_tag(person) == bl.person_tag(person)
    # a DIFFERENT person is not blocked
    assert not bl.is_blocked(os.urandom(32))
    # and the same person is NOT blocked in a DIFFERENT scope (scoped, not global)
    other_scope = BlockList(b"conversation-99")
    assert not other_scope.is_blocked(person)
