"""Space content + persistence + access gating (Phase B). Posting is gated by the space's ACCESS
tier (SELF / INVITE / MEMBER = allow-list via the authority engine; OPEN = verified-human + not-banned),
and each persistence mode witnesses the post at its own durability level (Present=nothing, Fading=TTL,
Private=ledgered, Public=globally anchored)."""

import pytest

from atlas.authority import fs_keygen
from atlas.crypto.sign import keypair_from_seed
from atlas.ledger.global_anchor import GlobalAnchorLog
from atlas.spaces.content import SpaceStore, AccessError, content_commitment
from atlas.spaces.kinds import make_space, invite, SpaceKind, PersistenceMode, Role, Access, IdentityTier

SID = b"space-1"


def _owner():
    return fs_keygen(bytes(range(32)), height=3)


def kp(n):
    return keypair_from_seed(bytes([n]) * 32)


A = kp(2)
MOD = kp(4)


def _chain(space, signer, who=A, role=Role.MEMBER):
    return [invite(space, signer, invitee=who.public, role=role)]


# --------------------------------------------------------------------------- allow-list (INVITE/MEMBER)
def test_guest_cannot_post_member_space():
    pub, signer = _owner()
    space = make_space(SID, SpaceKind.ORG, pub)                # MEMBER access
    store = SpaceStore(space)
    with pytest.raises(AccessError):                           # a GUEST (read-only) cannot post
        store.post(_chain(space, signer, role=Role.GUEST), author=b"aun", content=b"hi", now=1000)


def test_member_post_and_commitment():
    pub, signer = _owner()
    space = make_space(SID, SpaceKind.FRIENDS, pub, PersistenceMode.PRIVATE)   # INVITE access
    store = SpaceStore(space)
    item = store.post(_chain(space, signer), author=b"aun", content=b"hello", now=1000)
    assert item.content_hash == content_commitment(SID, b"aun", b"hello")
    assert item.persistence == PersistenceMode.PRIVATE


def test_self_space_only_owner_posts():
    pub, signer = _owner()
    space = make_space(SID, SpaceKind.SELF, pub)              # SELF access
    store = SpaceStore(space)
    with pytest.raises(AccessError):                          # a mere MEMBER can't post in a space of one
        store.post(_chain(space, signer, role=Role.MEMBER), author=b"aun", content=b"x", now=1000)
    owner_chain = _chain(space, signer, role=Role.OWNER)
    assert store.post(owner_chain, author=b"aun", content=b"mine", now=1000) is not None


# --------------------------------------------------------------------------- persistence witnesses
def test_present_stores_nothing():
    pub, signer = _owner()
    space = make_space(SID, SpaceKind.DIRECT, pub, PersistenceMode.PRESENT)
    store = SpaceStore(space)
    store.post(_chain(space, signer), author=b"aun", content=b"ephemeral", now=1000)
    assert store.live(1000) == []                             # live only — no stored copy
    assert len(store.ledger) == 0


def test_fading_prunes_after_ttl():
    pub, signer = _owner()
    space = make_space(SID, SpaceKind.FRIENDS, pub, PersistenceMode.FADING)
    store = SpaceStore(space)
    store.post(_chain(space, signer), author=b"aun", content=b"soon gone", now=100, ttl=50)
    assert len(store.live(120)) == 1                          # within TTL
    assert store.live(200) == []                              # expired -> pruned


def test_private_ledgered_not_globally_anchored():
    pub, signer = _owner()
    space = make_space(SID, SpaceKind.FRIENDS, pub, PersistenceMode.PRIVATE)
    store = SpaceStore(space, global_anchor=GlobalAnchorLog())
    store.post(_chain(space, signer), author=b"aun", content=b"private", now=1000)
    assert len(store.ledger) == 1                             # ledgered between the parties
    assert store.is_publicly_provable() is False              # but NOT anchored to the world


def test_public_anchored_globally():
    pub, signer = _owner()
    ga = GlobalAnchorLog()
    space = make_space(SID, SpaceKind.MOVEMENT, pub, PersistenceMode.PUBLIC)   # MEMBER access, PUBLIC
    store = SpaceStore(space, global_anchor=ga)
    store.post(_chain(space, signer), author=b"aun", content=b"public", now=1000)
    assert store.is_publicly_provable() is True               # provable to anyone
    assert ga.verify_chain() is True


def test_public_requires_a_global_anchor():
    pub, signer = _owner()
    space = make_space(SID, SpaceKind.MOVEMENT, pub, PersistenceMode.PUBLIC)
    store = SpaceStore(space)                                  # no global anchor
    with pytest.raises(AccessError):
        store.post(_chain(space, signer), author=b"aun", content=b"public", now=1000)


# --------------------------------------------------------------------------- OPEN (public commons)
def test_open_commons_verified_human_posts_without_invite():
    pub, _ = _owner()
    space = make_space(SID, SpaceKind.COMMONS, pub)           # OPEN access by default
    assert space.access == Access.OPEN
    store = SpaceStore(space, global_anchor=GlobalAnchorLog(),
                       is_verified_human=lambda h: h == b"aun")
    item = store.post([], author=b"aun", content=b"hello world", now=1000)   # NO invite chain
    assert item.content_hash == content_commitment(SID, b"aun", b"hello world")


def test_open_commons_rejects_unverified():
    pub, _ = _owner()
    space = make_space(SID, SpaceKind.COMMONS, pub)
    store = SpaceStore(space, is_verified_human=lambda h: False)   # not a verified human
    with pytest.raises(AccessError):
        store.post([], author=b"sybil", content=b"spam", now=1000)


def test_open_commons_fail_closed_without_predicate():
    pub, _ = _owner()
    space = make_space(SID, SpaceKind.COMMONS, pub)
    store = SpaceStore(space)                                  # no personhood predicate wired
    with pytest.raises(AccessError):                          # OPEN posting fails closed
        store.post([], author=b"aun", content=b"x", now=1000)


# --------------------------------------------------------------------------- block-list moderation
def test_moderator_can_ban_and_ban_blocks_posting():
    pub, signer = _owner()
    space = make_space(SID, SpaceKind.COMMONS, pub)
    store = SpaceStore(space, global_anchor=GlobalAnchorLog(), is_verified_human=lambda h: True)
    assert store.post([], author=b"troll", content=b"ok so far", now=1000) is not None
    mod_chain = [invite(space, signer, invitee=MOD.public, role=Role.MODERATOR)]
    store.ban(mod_chain, target=b"troll", now=1000)           # a MODERATOR bans the troll
    with pytest.raises(AccessError):                          # now the troll is blocked
        store.post([], author=b"troll", content=b"more spam", now=1001)


def test_non_moderator_cannot_ban():
    pub, signer = _owner()
    space = make_space(SID, SpaceKind.COMMONS, pub)
    store = SpaceStore(space, is_verified_human=lambda h: True)
    member_chain = _chain(space, signer, role=Role.MEMBER)    # only a MEMBER, not a MOD
    with pytest.raises(AccessError):
        store.ban(member_chain, target=b"rival", now=1000)    # can't ban a rival


# --------------------------------------------------------------------------- identity tier (orthogonal)
def test_verified_person_space_requires_personhood_even_for_a_member():
    pub, signer = _owner()
    # a member-gated ORG, but escalated to VERIFIED_PERSON identity (accountable pseudonymity)
    space = make_space(SID, SpaceKind.ORG, pub, identity=IdentityTier.VERIFIED_PERSON)
    chain = _chain(space, signer, role=Role.MEMBER)
    no_ph = SpaceStore(space)                                  # holds the grant but no personhood proof
    with pytest.raises(AccessError):
        no_ph.post(chain, author=b"aun", content=b"hi", now=1000)
    ph = SpaceStore(space, is_verified_human=lambda h: h == b"aun")
    assert ph.post(chain, author=b"aun", content=b"hi", now=1000) is not None


def test_anonymous_space_allows_posting_without_personhood():
    pub, _ = _owner()
    # OPEN + ANONYMOUS: the public square with anonymity — no invite, no personhood check.
    space = make_space(SID, SpaceKind.COMMONS, pub, PersistenceMode.PRESENT,
                       identity=IdentityTier.ANONYMOUS)
    store = SpaceStore(space)                                  # no personhood predicate at all
    assert store.post([], author=b"anon", content=b"hi", now=1000) is not None
