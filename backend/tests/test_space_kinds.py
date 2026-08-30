"""Space kinds + persistence + authority-based invitation (Phase B).

The taxonomy is locked; membership rides the authority engine, so invitation inherits its guarantees:
delegation attenuates, non-delegable members can't invite, cross-space grants don't verify, and the
owner is a forward-secure root (no backdating).
"""

import pytest

from atlas.authority import AuthorityError
from atlas.authority.fs_sign import fs_keygen
from atlas.crypto.sign import keypair_from_seed
from atlas.spaces.kinds import (
    SpaceKind, PersistenceMode, Role, make_space, direct, commons,
    invite, sub_invite, member_role, persistence_backend,
)

SID = b"space-42"


def _owner():
    return fs_keygen(bytes(range(32)), height=3)     # (FSPublicKey, FSSigner)


def kp(n):
    return keypair_from_seed(bytes([n]) * 32)


A, B = kp(2), kp(3)


def test_constructors_and_default_persistence():
    pub, _ = _owner()
    assert commons(SID, pub).kind == SpaceKind.COMMONS
    assert commons(SID, pub).persistence == PersistenceMode.PUBLIC     # default per kind
    assert direct(SID, pub).persistence == PersistenceMode.PRIVATE
    # any space, any mode — override the default
    assert commons(SID, pub, PersistenceMode.PRESENT).persistence == PersistenceMode.PRESENT


def test_persistence_escalation_and_backend():
    assert (PersistenceMode.PRESENT < PersistenceMode.FADING
            < PersistenceMode.PRIVATE < PersistenceMode.PUBLIC)       # least -> most durable
    assert "GlobalAnchor" in persistence_backend(PersistenceMode.PUBLIC)
    assert "no retention" in persistence_backend(PersistenceMode.PRESENT)


def test_invite_and_member_role():
    pub, signer = _owner()
    space = make_space(SID, SpaceKind.FRIENDS, pub)
    g = invite(space, signer, invitee=A.public, role=Role.MEMBER)
    assert member_role(space, [g], now=1000) == Role.MEMBER


def test_delegated_invite_attenuates():
    pub, signer = _owner()
    space = make_space(SID, SpaceKind.HOST, pub)
    admin = invite(space, signer, invitee=A.public, role=Role.ADMIN, delegable=True)
    guest = sub_invite(admin, A, invitee=B.public, role=Role.GUEST)   # admin invites a guest
    assert member_role(space, [admin, guest], now=1000) == Role.GUEST
    with pytest.raises(AuthorityError):                               # can't grant ABOVE own role
        sub_invite(admin, A, invitee=B.public, role=Role.OWNER)


def test_nondelegable_member_cannot_invite():
    pub, signer = _owner()
    space = make_space(SID, SpaceKind.FRIENDS, pub)
    member = invite(space, signer, invitee=A.public, role=Role.MEMBER)   # delegable=False
    with pytest.raises(AuthorityError):
        sub_invite(member, A, invitee=B.public, role=Role.GUEST)


def test_cross_space_grant_rejected():
    pub, signer = _owner()
    space_a = commons(b"space-A", pub)
    space_b = commons(b"space-B", pub)                # same owner, different space
    g = invite(space_a, signer, invitee=A.public, role=Role.MEMBER)
    assert member_role(space_a, [g], now=1000) == Role.MEMBER
    with pytest.raises(AuthorityError):               # a grant for A does not verify in B
        member_role(space_b, [g], now=1000)


def test_role_gate():
    from atlas.spaces.kinds import has_role
    pub, signer = _owner()
    space = make_space(SID, SpaceKind.FRIENDS, pub)
    g = invite(space, signer, invitee=A.public, role=Role.MEMBER)
    assert has_role(space, [g], at_least=Role.MEMBER, now=1000) is True
    assert has_role(space, [g], at_least=Role.ADMIN, now=1000) is False       # fail-closed gate
    # a garbage chain -> False, never raises
    bad = make_space(b"other", SpaceKind.COMMONS, pub)
    assert has_role(bad, [g], at_least=Role.GUEST, now=1000) is False
