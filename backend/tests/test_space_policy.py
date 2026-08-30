"""Space policy — membership + roles, quorum-gated governance, append-only hash-chained access log."""
import pytest

from atlas.crypto.sign import keypair_from_seed
from atlas.spaces.space_policy import (
    NotAuthorized, PolicyError, Role, SpacePolicy, StaleChange,
)


def kp(n):
    return keypair_from_seed(bytes([n]) * 32)


def test_genesis_creator_is_sole_governor():
    creator = kp(1)
    p = SpacePolicy.genesis(b"space:acme", creator.public)
    assert p.role_of(creator.public) == Role.GOVERNOR
    assert p.quorum == 1
    assert p.verify_log()
    assert p.head() != b""


def test_governor_grants_reader_and_capabilities_apply():
    gov, alice = kp(1), kp(2)
    p = SpacePolicy.genesis(b"s", gov.public)
    ch = p.propose("grant", target=alice.public, role=Role.READER, epoch=1)
    p.authorize(ch, [(gov.public, sign_change(gov, ch))])

    assert p.can(alice.public, Role.READER)
    assert not p.can(alice.public, Role.CONTRIBUTOR)     # reader can't write
    assert p.can(gov.public, Role.GOVERNOR)
    assert p.verify_log()


def test_change_without_quorum_is_rejected():
    gov, outsider, target = kp(1), kp(9), kp(2)
    p = SpacePolicy.genesis(b"s", gov.public)
    ch = p.propose("grant", target=target.public, role=Role.READER, epoch=1)
    # A non-governor's signature doesn't count.
    with pytest.raises(NotAuthorized):
        p.authorize(ch, [(outsider.public, sign_change(outsider, ch))])
    assert p.role_of(target.public) is None


def test_two_of_two_governance_quorum():
    g1, g2, target = kp(1), kp(2), kp(3)
    p = SpacePolicy.genesis(b"s", g1.public)
    # add g2 as a governor (quorum still 1)
    add_g2 = p.propose("grant", target=g2.public, role=Role.GOVERNOR, epoch=1)
    p.authorize(add_g2, [(g1.public, sign_change(g1, add_g2))])
    # raise quorum to 2 (needs 1 approval at current quorum)
    setq = p.propose("set_quorum", quorum=2, epoch=2)
    p.authorize(setq, [(g1.public, sign_change(g1, setq))])
    assert p.quorum == 2

    # now a grant needs BOTH governors
    ch = p.propose("grant", target=target.public, role=Role.CONTRIBUTOR, epoch=3)
    with pytest.raises(NotAuthorized):
        p.authorize(ch, [(g1.public, sign_change(g1, ch))])            # only one -> fail
    # re-propose against the (unchanged) head and approve with both
    ch2 = p.propose("grant", target=target.public, role=Role.CONTRIBUTOR, epoch=3)
    p.authorize(ch2, [(g1.public, sign_change(g1, ch2)), (g2.public, sign_change(g2, ch2))])
    assert p.can(target.public, Role.CONTRIBUTOR)


def test_duplicate_governor_signature_counts_once():
    g1, g2, target = kp(1), kp(2), kp(3)
    p = SpacePolicy.genesis(b"s", g1.public)
    add = p.propose("grant", target=g2.public, role=Role.GOVERNOR, epoch=1)
    p.authorize(add, [(g1.public, sign_change(g1, add))])
    setq = p.propose("set_quorum", quorum=2, epoch=2)
    p.authorize(setq, [(g1.public, sign_change(g1, setq))])

    ch = p.propose("grant", target=target.public, role=Role.READER, epoch=3)
    # g1 signs twice — must still count as ONE distinct governor
    with pytest.raises(NotAuthorized):
        p.authorize(ch, [(g1.public, sign_change(g1, ch)), (g1.public, sign_change(g1, ch))])


def test_revoke_is_forward_only_and_logged():
    gov, alice = kp(1), kp(2)
    p = SpacePolicy.genesis(b"s", gov.public)
    grant = p.propose("grant", target=alice.public, role=Role.READER, epoch=1)
    p.authorize(grant, [(gov.public, sign_change(gov, grant))])
    rev = p.propose("revoke", target=alice.public, epoch=2)
    p.authorize(rev, [(gov.public, sign_change(gov, rev))])
    assert p.role_of(alice.public) is None            # no future access
    assert len(p.log) == 3                            # genesis + grant + revoke all retained
    assert p.verify_log()


def test_stale_change_rejected():
    g1, a, b = kp(1), kp(2), kp(3)
    p = SpacePolicy.genesis(b"s", g1.public)
    first = p.propose("grant", target=a.public, role=Role.READER, epoch=1)
    stale = p.propose("grant", target=b.public, role=Role.READER, epoch=1)   # same head as `first`
    p.authorize(first, [(g1.public, sign_change(g1, first))])                # head moves
    with pytest.raises(StaleChange):
        p.authorize(stale, [(g1.public, sign_change(g1, stale))])            # approved vs old head


def test_tampering_with_a_past_entry_breaks_the_chain():
    gov, alice = kp(1), kp(2)
    p = SpacePolicy.genesis(b"s", gov.public)
    grant = p.propose("grant", target=alice.public, role=Role.READER, epoch=1)
    p.authorize(grant, [(gov.public, sign_change(gov, grant))])
    assert p.verify_log()
    # silently rewrite history
    p.log[1].__dict__["change_body"] = b"forged"
    assert p.verify_log() is False


def test_members_at_role_is_the_eligible_set_basis():
    g1, g2, worker = kp(1), kp(2), kp(3)
    p = SpacePolicy.genesis(b"s", g1.public)
    for who, role, ep in [(g2, Role.GOVERNOR, 1), (worker, Role.CONTRIBUTOR, 2)]:
        ch = p.propose("grant", target=who.public, role=role, epoch=ep)
        p.authorize(ch, [(g1.public, sign_change(g1, ch))])
    assert set(p.members_at(Role.GOVERNOR)) == {g1.public.encode(), g2.public.encode()}
    assert len(p.members_at(Role.CONTRIBUTOR)) == 3    # g1, g2, worker


# helper: sign a change body with a keypair
def sign_change(kpair, change):
    from atlas.crypto.sign import sign
    return sign(kpair, change.body())
