"""Mutual-consent forensic collection: a trusted contact can collect your panic forensics only when
BOTH of you agreed — the contact holds their share (accepted), the owner released theirs (on panic)."""
import pytest

from atlas.keys import guardian_forensics as gf


def test_both_shares_collect_the_capture():
    key = gf.new_forensic_key()
    blob = gf.seal_forensic(key, b"black-box: location trail + ambient audio")
    grant = gf.setup_guardian(key)

    # Panic fires -> owner releases owner_share to the contact, who already holds contact_share.
    recovered = gf.collect_forensic_key(grant.contact_share, grant.owner_share)
    assert recovered == key
    assert gf.open_forensic(recovered, blob) == b"black-box: location trail + ambient audio"


def test_contact_share_alone_is_inert():
    # The contact holding only their share (owner never triggered panic) cannot collect.
    key = gf.new_forensic_key()
    grant = gf.setup_guardian(key)
    with pytest.raises(gf.ConsentIncomplete):
        gf.collect_forensic_key(grant.contact_share, grant.contact_share)  # no owner release -> not two distinct shares


def test_owner_share_alone_is_inert():
    key = gf.new_forensic_key()
    grant = gf.setup_guardian(key)
    with pytest.raises(gf.ConsentIncomplete):
        gf.collect_forensic_key(grant.owner_share, grant.owner_share)


def test_foreign_owner_share_collects_nothing():
    # A contact pairing THEIR share with a DIFFERENT owner's owner-share reconstructs a wrong key
    # that fails to open the capture. Shares are per-relationship; cross-pairing yields nothing.
    key_a = gf.new_forensic_key()
    blob_a = gf.seal_forensic(key_a, b"owner A capture")
    grant_a = gf.setup_guardian(key_a)

    grant_b = gf.setup_guardian(gf.new_forensic_key())  # a different owner/relationship

    wrong = gf.collect_forensic_key(grant_a.contact_share, grant_b.owner_share)
    assert wrong != key_a
    with pytest.raises(Exception):
        gf.open_forensic(wrong, blob_a)  # AEAD rejects the wrong key


def test_wrong_forensic_key_never_opens():
    key = gf.new_forensic_key()
    blob = gf.seal_forensic(key, b"secret")
    with pytest.raises(Exception):
        gf.open_forensic(gf.new_forensic_key(), blob)


def test_forensic_key_minimum_length_enforced():
    with pytest.raises(ValueError):
        gf.setup_guardian(b"tooshort")


def test_shares_are_opaque_bytes_roundtrip():
    # Shares must survive transport (owner -> contact over the relay) as bytes.
    key = gf.new_forensic_key()
    grant = gf.setup_guardian(key)
    from atlas.crypto.shamir import Share
    c = Share.decode(grant.contact_share.encode())
    o = Share.decode(grant.owner_share.encode())
    assert gf.collect_forensic_key(c, o) == key
