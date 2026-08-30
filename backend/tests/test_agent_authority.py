"""Agent authority: the leash AND the gate composed — an agent can't self-declare being an individual."""
import pytest

from atlas.agent_authority import agent_may_supply
from atlas.agent_delegation import delegate
from atlas.crypto.sign import keypair_from_seed
from atlas.issuers import Issuer
from atlas.marketplace import EntityClass
from atlas.participant import create_profile

NOW = 100
SPACE = b"space:market"


def kp(n):
    return keypair_from_seed(bytes([n]) * 32)


def _profile(k, ec=EntityClass.INDIVIDUAL):
    return create_profile(handle=bytes([9]) * 32, public=k.public, entity_class=ec)


def test_credentialed_root_lets_its_agent_sell():
    human, agent = kp(1), kp(2)
    profile = _profile(human)
    verifier = Issuer(kp(5), "Real-ID Verifier")
    profile.hold(verifier.issue_real_id(subject=profile.handle))

    chain = [delegate(human, principal_class=EntityClass.INDIVIDUAL, agent=agent.public,
                      capabilities=["sell"], scope=SPACE, not_after=200)]
    assert agent_may_supply(chain, action="sell", scope=SPACE, now=NOW, root_profile=profile,
                            trusted_verifier_keys={verifier.public.encode()})


def test_uncredentialed_root_cannot_sell_even_with_a_valid_chain():
    human, agent = kp(1), kp(2)
    profile = _profile(human)                      # NO real-id credential held
    verifier = Issuer(kp(5), "Real-ID Verifier")
    chain = [delegate(human, principal_class=EntityClass.INDIVIDUAL, agent=agent.public,
                      capabilities=["sell"], scope=SPACE, not_after=200)]
    assert not agent_may_supply(chain, action="sell", scope=SPACE, now=NOW, root_profile=profile,
                                trusted_verifier_keys={verifier.public.encode()})


def test_agent_self_declaring_root_is_rejected():
    # the classic attack: an agent mints itself a root delegation claiming to be an individual.
    rogue, sub = kp(1), kp(2)
    profile = _profile(rogue, EntityClass.AGENT)
    chain = [delegate(rogue, principal_class=EntityClass.AGENT, agent=sub.public,
                      capabilities=["sell"], scope=SPACE, not_after=200)]
    # verify_chain already rejects an agent-rooted chain -> no authority, regardless of credentials
    assert not agent_may_supply(chain, action="sell", scope=SPACE, now=NOW, root_profile=profile,
                                trusted_verifier_keys=set())


def test_profile_must_be_the_chain_root():
    human, agent, imposter = kp(1), kp(2), kp(7)
    verifier = Issuer(kp(5), "V")
    imposter_profile = _profile(imposter)          # a DIFFERENT, credentialed profile
    imposter_profile.hold(verifier.issue_real_id(subject=imposter_profile.handle))
    chain = [delegate(human, principal_class=EntityClass.INDIVIDUAL, agent=agent.public,
                      capabilities=["sell"], scope=SPACE, not_after=200)]
    # can't launder a stranger's credential in for THIS chain's root
    assert not agent_may_supply(chain, action="sell", scope=SPACE, now=NOW, root_profile=imposter_profile,
                                trusted_verifier_keys={verifier.public.encode()})


def test_capability_not_granted_is_rejected():
    human, agent = kp(1), kp(2)
    profile = _profile(human)
    verifier = Issuer(kp(5), "V")
    profile.hold(verifier.issue_real_id(subject=profile.handle))
    chain = [delegate(human, principal_class=EntityClass.INDIVIDUAL, agent=agent.public,
                      capabilities=["read"], scope=SPACE, not_after=200)]   # only "read"
    assert not agent_may_supply(chain, action="sell", scope=SPACE, now=NOW, root_profile=profile,
                                trusted_verifier_keys={verifier.public.encode()})


def test_org_root_needs_registration_too():
    officer, agent = kp(1), kp(2)
    org = _profile(officer, EntityClass.FOR_PROFIT)
    verifier, registry = Issuer(kp(5), "V"), Issuer(kp(6), "Registry")
    org.hold(verifier.issue_real_id(subject=org.handle))
    vkeys, rkeys = {verifier.public.encode()}, {registry.public.encode()}
    chain = [delegate(officer, principal_class=EntityClass.FOR_PROFIT, agent=agent.public,
                      capabilities=["sell"], scope=SPACE, not_after=200)]
    # real-id but no registration -> org can't operate -> agent can't sell
    assert not agent_may_supply(chain, action="sell", scope=SPACE, now=NOW, root_profile=org,
                                trusted_verifier_keys=vkeys, trusted_registry_keys=rkeys)
    org.hold(registry.issue_registration(subject=org.handle))
    assert agent_may_supply(chain, action="sell", scope=SPACE, now=NOW, root_profile=org,
                            trusted_verifier_keys=vkeys, trusted_registry_keys=rkeys)
