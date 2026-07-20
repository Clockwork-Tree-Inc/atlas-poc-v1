"""Tests for group spaces (TRUST_LAYER.md #12)."""

import pytest

from atlas.crypto.primitives import random_bytes
from atlas.realid.space_pseudonym import join_space
from atlas.spaces.space import (
    AccessError,
    GovernanceError,
    Space,
    SpaceError,
    SpacePolicy,
    add_member,
    create_space,
    open_vault,
    remove_member,
    seal_to_vault,
)

SID = b"family"


def _roots(n):
    return [random_bytes(32) for _ in range(n)]


def _policy(access=2, gov=2):
    return SpacePolicy(access_threshold=access, governance_threshold=gov)


# --------------------------------------------------------------------------- creation
def test_members_join_under_nyms_not_roots():
    roots = _roots(3)
    space, roster = create_space(SID, roots, _policy())
    assert space.size() == 3
    for r in roots:
        nym = join_space(r, SID).nym
        assert space.is_member(nym) and nym in roster
        assert r not in space.member_nyms                 # the root is never in the space


def test_policy_validation():
    with pytest.raises(SpaceError):
        create_space(SID, _roots(3), _policy(access=1))   # k must be > 1
    with pytest.raises(SpaceError):
        create_space(SID, _roots(2), _policy(access=3))   # k <= n


def test_duplicate_member_rejected():
    r = random_bytes(32)
    with pytest.raises(SpaceError):
        create_space(SID, [r, r], _policy())


# --------------------------------------------------------------------------- vault
def test_seal_and_open_with_threshold():
    roots = _roots(3)
    space, roster = create_space(SID, roots, _policy(access=2))
    shares = list(roster.values())
    item = seal_to_vault(space, b"family photo", shares[:2])
    assert b"family photo" not in item.ciphertext          # only ciphertext stored
    assert open_vault(space, item, shares[:2]) == b"family photo"
    # any 2-of-3 present members can open it
    assert open_vault(space, item, [shares[1], shares[2]]) == b"family photo"


def test_below_access_threshold_fails_closed():
    roots = _roots(3)
    space, roster = create_space(SID, roots, _policy(access=2))
    shares = list(roster.values())
    item = seal_to_vault(space, b"secret", shares[:2])
    with pytest.raises(AccessError):
        open_vault(space, item, shares[:1])                # only 1 present


def test_tenant_isolation_across_spaces():
    roots = _roots(3)
    a, ra = create_space(b"space-A", roots, _policy(access=2))
    b, rb = create_space(b"space-B", roots, _policy(access=2))
    item = seal_to_vault(a, b"A only", list(ra.values())[:2])
    # same humans, different space -> different nyms, different root/keyspace; wrong-space rejected
    with pytest.raises(AccessError):
        open_vault(b, item, list(rb.values())[:2])


# --------------------------------------------------------------------------- reshare / governance
def test_add_member_reshares_and_vault_survives():
    roots = _roots(3)
    space, roster = create_space(SID, roots, _policy(access=2, gov=2))
    item = seal_to_vault(space, b"shared note", list(roster.values())[:2])

    newcomer = random_bytes(32)
    updated, new_roster = add_member(space, newcomer, roots, list(roster.values())[:2])
    assert updated.size() == 4 and join_space(newcomer, SID).nym in new_roster
    # the SAME root backs the vault: the old item still opens with the NEW shares
    assert open_vault(updated, item, list(new_roster.values())[:2]) == b"shared note"


def test_removed_member_is_truly_revoked():
    # TRUE revocation: removal rotates the root + re-encrypts the vault, so NO old share opens it —
    # not even a full OLD quorum (the removed member's old share + a retained member's old share).
    roots = _roots(3)
    space, roster = create_space(SID, roots, _policy(access=2, gov=2))
    item = seal_to_vault(space, b"members only", list(roster.values())[:2])

    removed_root = roots[2]
    removed_old = roster[join_space(removed_root, SID).nym]
    survivor_old = roster[join_space(roots[0], SID).nym]      # a retained member's OLD share
    updated, new_roster = remove_member(space, removed_root, roots[:2], list(roster.values())[:2])
    assert updated.size() == 2
    new_shares = list(new_roster.values())
    rekeyed_item = updated.store[0]          # the vault item, re-encrypted under the NEW root

    # a full OLD quorum reconstructs the OLD root, but the current vault is under the NEW root.
    with pytest.raises(AccessError):
        open_vault(updated, rekeyed_item, [removed_old, survivor_old])
    # mixing an old share with a new share also fails (different polynomials).
    with pytest.raises(AccessError):
        open_vault(updated, rekeyed_item, [new_shares[0], removed_old])
    # only the current members, with their new shares, open the re-keyed vault.
    assert open_vault(updated, rekeyed_item, new_shares[:2]) == b"members only"


def test_governance_below_access_is_rejected():
    # gov < access would reshare/reconstruct the root from too few points -> silent data loss.
    with pytest.raises(SpaceError):
        create_space(SID, _roots(4), _policy(access=3, gov=2))


def test_governance_threshold_enforced():
    roots = _roots(3)
    space, roster = create_space(SID, roots, _policy(access=2, gov=3))
    with pytest.raises(GovernanceError):
        add_member(space, random_bytes(32), roots, list(roster.values())[:2])  # only 2 authorize, need 3


def test_add_existing_member_rejected():
    roots = _roots(3)
    space, roster = create_space(SID, roots, _policy())
    with pytest.raises(SpaceError):
        add_member(space, roots[0], roots, list(roster.values())[:2])
