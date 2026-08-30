"""Agent delegation — the leash: capability-scoped, expiring, always rooted at a human/business."""
import pytest

from atlas.agent_delegation import (
    Delegation, authorized, delegate, root_principal, verify_chain, verify_link,
)
from atlas.crypto.sign import keypair_from_seed
from atlas.marketplace import EntityClass


def kp(n):
    return keypair_from_seed(bytes([n]) * 32)


NOW = 100
SPACE = b"space:acme"


def test_individual_delegates_to_agent():
    human, agent = kp(1), kp(2)
    d = delegate(human, principal_class=EntityClass.INDIVIDUAL, agent=agent.public,
                 capabilities=["read", "post"], scope=SPACE, not_after=200)
    assert verify_link(d, now=NOW)
    assert verify_chain([d], now=NOW)
    assert authorized([d], capability="post", scope=SPACE, now=NOW)
    assert not authorized([d], capability="delete", scope=SPACE, now=NOW)   # capability not granted


def test_business_can_be_principal():
    biz, agent = kp(1), kp(2)
    d = delegate(biz, principal_class=EntityClass.FOR_PROFIT, agent=agent.public,
                 capabilities=["sell"], scope=SPACE, not_after=200)
    assert verify_chain([d], now=NOW)
    who, cls = root_principal([d])
    assert cls is EntityClass.FOR_PROFIT


def test_agent_cannot_be_a_root_principal():
    rogue_agent, sub = kp(1), kp(2)
    # an agent tries to root a chain (no parent) — rejected: agents can't originate authority
    d = delegate(rogue_agent, principal_class=EntityClass.AGENT, agent=sub.public,
                 capabilities=["read"], scope=SPACE, not_after=200)
    assert verify_link(d, now=NOW) is False
    assert verify_chain([d], now=NOW) is False


def test_expired_delegation_is_invalid():
    human, agent = kp(1), kp(2)
    d = delegate(human, principal_class=EntityClass.INDIVIDUAL, agent=agent.public,
                 capabilities=["read"], scope=SPACE, not_after=50)
    assert verify_link(d, now=NOW) is False                 # NOW=100 > 50
    assert not authorized([d], capability="read", scope=SPACE, now=NOW)


def test_tampered_signature_fails():
    human, agent = kp(1), kp(2)
    d = delegate(human, principal_class=EntityClass.INDIVIDUAL, agent=agent.public,
                 capabilities=["read"], scope=SPACE, not_after=200)
    forged = Delegation(**{**d.__dict__, "capabilities": ("read", "admin")})   # add a capability post-sign
    assert verify_link(forged, now=NOW) is False


def test_valid_subdelegation_attenuates_and_roots():
    human, planner, worker = kp(1), kp(2), kp(3)
    root = delegate(human, principal_class=EntityClass.INDIVIDUAL, agent=planner.public,
                    capabilities=["read", "post", "pay"], scope=b"", not_after=300)
    # planner sub-delegates a NARROWER capability set + scope + earlier expiry to a worker agent
    sub = delegate(planner, principal_class=EntityClass.AGENT, agent=worker.public,
                   capabilities=["read"], scope=SPACE, not_after=250, parent=root.id())
    chain = [root, sub]
    assert verify_chain(chain, now=NOW)
    assert authorized(chain, capability="read", scope=SPACE, now=NOW)
    # the worker never got "pay" — attenuation holds
    assert not authorized(chain, capability="pay", scope=SPACE, now=NOW)
    who, cls = root_principal(chain)
    assert cls is EntityClass.INDIVIDUAL                     # resolves to the human


def test_subdelegation_cannot_widen_capabilities():
    human, planner, worker = kp(1), kp(2), kp(3)
    root = delegate(human, principal_class=EntityClass.INDIVIDUAL, agent=planner.public,
                    capabilities=["read"], scope=b"", not_after=300)
    wider = delegate(planner, principal_class=EntityClass.AGENT, agent=worker.public,
                     capabilities=["read", "pay"], scope=b"", not_after=300, parent=root.id())  # widen!
    assert verify_chain([root, wider], now=NOW) is False


def test_subdelegation_cannot_outlive_parent():
    human, planner, worker = kp(1), kp(2), kp(3)
    root = delegate(human, principal_class=EntityClass.INDIVIDUAL, agent=planner.public,
                    capabilities=["read"], scope=b"", not_after=200)
    longer = delegate(planner, principal_class=EntityClass.AGENT, agent=worker.public,
                      capabilities=["read"], scope=b"", not_after=999, parent=root.id())  # outlives!
    assert verify_chain([root, longer], now=NOW) is False


def test_broken_chain_link_fails():
    human, planner, worker, imposter = kp(1), kp(2), kp(3), kp(4)
    root = delegate(human, principal_class=EntityClass.INDIVIDUAL, agent=planner.public,
                    capabilities=["read"], scope=b"", not_after=300)
    # a link whose principal is NOT the previously-leashed agent (imposter forges a parent link)
    orphan = delegate(imposter, principal_class=EntityClass.AGENT, agent=worker.public,
                      capabilities=["read"], scope=b"", not_after=300, parent=root.id())
    assert verify_chain([root, orphan], now=NOW) is False


def test_global_scope_covers_any_space():
    human, agent = kp(1), kp(2)
    d = delegate(human, principal_class=EntityClass.INDIVIDUAL, agent=agent.public,
                 capabilities=["read"], scope=b"", not_after=300)
    assert authorized([d], capability="read", scope=b"any-space", now=NOW)


def test_entity_class_helpers():
    assert EntityClass.FOR_PROFIT.is_organization and EntityClass.NONPROFIT.is_organization
    assert not EntityClass.INDIVIDUAL.is_organization and not EntityClass.AGENT.is_organization
    assert EntityClass.INDIVIDUAL.can_be_principal and EntityClass.FOR_PROFIT.can_be_principal
    assert not EntityClass.AGENT.can_be_principal
