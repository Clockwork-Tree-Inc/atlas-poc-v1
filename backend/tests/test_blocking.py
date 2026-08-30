"""Space identity policy + ZK-enforced person-scoped blocking: the participant PRESENTS a verified
person-tag proof (root never seen); one-person-one-account; blocks survive a fresh pseudonym;
open-allows-anon; identified = caller-ID; per-space vs personal-global (only within your authority);
declared/revocable AI agents."""

import os

from atlas.spaces.blocking import AuthorityDomain, IdentityPolicy, Space
from atlas.zk.person_tag import commit_root, nullifier, prove_person_tag, root_scalar


def _proof(root: bytes, scope: bytes, epoch: int, nonce: bytes):
    """A participant's ZK person-tag presentation for a scope (the host verifies it; never the root)."""
    x = root_scalar(root)
    C, s = commit_root(x)
    return prove_person_tag(x, s, C, scope, epoch=epoch, nonce=nonce)


def _tag(root: bytes, scope: bytes) -> int:
    return nullifier(root_scalar(root), scope)


def _fresh():
    return 1, os.urandom(16)          # (epoch, verifier nonce)


def test_one_person_one_account_and_block_survives_new_pseudonym():
    root = os.urandom(32)
    s = Space(scope=b"room-1", policy=IdentityPolicy.VERIFIED_HUMAN)
    e, n = _fresh()
    assert s.admit(_proof(root, b"room-1", e, n), epoch=e, nonce=n)   # admitted (verified, unblocked)
    s.block(_tag(root, b"room-1"))                                    # block this person by their tag N
    # a "new pseudonym" = a fresh proof (new epoch/nonce) but the SAME root+scope -> SAME N -> still out
    e2, n2 = _fresh()
    assert not s.admit(_proof(root, b"room-1", e2, n2), epoch=e2, nonce=n2)


def test_open_policy_allows_anonymous():
    s = Space(scope=b"open", policy=IdentityPolicy.OPEN)
    e, n = _fresh()
    assert s.admit(None, epoch=e, nonce=n)                           # anonymous; no proof, no blocking


def test_verified_human_requires_a_valid_fresh_proof_for_this_scope():
    s = Space(scope=b"room", policy=IdentityPolicy.VERIFIED_HUMAN)
    e, n = _fresh()
    assert not s.admit(None, epoch=e, nonce=n)                       # no proof -> refused
    assert not s.admit(_proof(os.urandom(32), b"other", e, n), epoch=e, nonce=n)  # wrong scope
    p = _proof(os.urandom(32), b"room", e, n)
    assert not s.admit(p, epoch=e + 1, nonce=n)                      # stale epoch (replay) -> refused
    assert s.admit(p, epoch=e, nonce=n)                              # correct -> admitted


def test_identified_policy_is_caller_id():
    root = os.urandom(32)
    s = Space(scope=b"vip", policy=IdentityPolicy.IDENTIFIED)
    e, n = _fresh()
    p = _proof(root, b"vip", e, n)
    assert not s.admit(p, epoch=e, nonce=n, identified=False)        # must present Real-ID / verified-org
    assert s.admit(p, epoch=e, nonce=n, identified=True)


def test_per_space_block_is_scoped():
    root = os.urandom(32)
    a = Space(scope=b"space-A", policy=IdentityPolicy.VERIFIED_HUMAN)
    b = Space(scope=b"space-B", policy=IdentityPolicy.VERIFIED_HUMAN)
    a.block(_tag(root, b"space-A"))
    ea, na = _fresh()
    eb, nb = _fresh()
    assert not a.admit(_proof(root, b"space-A", ea, na), epoch=ea, nonce=na)   # blocked in A
    assert b.admit(_proof(root, b"space-B", eb, nb), epoch=eb, nonce=nb)       # NOT in B (per-space)


def test_personal_global_block_only_within_your_authority():
    root = os.urandom(32)
    mine = AuthorityDomain(authority_id=b"authority-me")
    # spaces that participate in personal-global blocking use the DOMAIN's scope
    a = Space(scope=b"authority-me", policy=IdentityPolicy.VERIFIED_HUMAN, domain=mine)
    b = Space(scope=b"authority-me", policy=IdentityPolicy.VERIFIED_HUMAN, domain=mine)
    other = Space(scope=b"authority-other", policy=IdentityPolicy.VERIFIED_HUMAN,
                  domain=AuthorityDomain(b"authority-other"))
    mine.block(_tag(root, b"authority-me"))                          # personal-global across MY domain
    ea, na = _fresh()
    eb, nb = _fresh()
    eo, no = _fresh()
    assert not a.admit(_proof(root, b"authority-me", ea, na), epoch=ea, nonce=na)   # blocked
    assert not b.admit(_proof(root, b"authority-me", eb, nb), epoch=eb, nonce=nb)   # across ALL my spaces
    assert other.admit(_proof(root, b"authority-other", eo, no), epoch=eo, nonce=no)  # not my authority


def test_ai_agent_is_declared_human_rooted_and_revocable():
    lab = AuthorityDomain(authority_id=b"lab")
    lab_space = Space(scope=b"lab", policy=IdentityPolicy.IDENTIFIED, domain=lab)
    assistant = os.urandom(16)
    assert not lab_space.admit_agent(assistant)                      # not delegated -> refused
    lab.delegate_agent(assistant)
    assert lab_space.admit_agent(assistant)                          # admitted in the AGENT lane
    lab.revoke_agent(assistant)
    assert not lab_space.admit_agent(assistant)                      # revoke -> cut off


def test_agent_delegation_is_scoped_to_the_authority():
    mine = AuthorityDomain(b"me")
    other = AuthorityDomain(b"other")
    family = Space(scope=b"family", policy=IdentityPolicy.VERIFIED_HUMAN, domain=mine)
    their_lab = Space(scope=b"their-lab", policy=IdentityPolicy.VERIFIED_HUMAN, domain=other)
    butler = os.urandom(16)
    mine.delegate_agent(butler)
    assert family.admit_agent(butler)                                # my butler in my family space
    assert not their_lab.admit_agent(butler)                         # NOT in another authority's domain
