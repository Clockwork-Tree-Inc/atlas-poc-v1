"""Adversarial tests for the recovery anchor — the real-you/digital-you bridge.

Every rung is fail-closed: a wrong or missing factor RAISES, it never degrades to a
partial or silent success. Also asserts the core privacy property: the recovery
pseudonym (real you) is unlinked to the System-ID (digital you), and the server-side
record is opaque without the full ceremony.

TRUST_LAYER.md #6: this module stores NO biometric and runs NO fuzzy extractor. At the
physical-self / total-loss tier the face check IS the live recovery person (a decentralized,
accountable human), so the factors are (name+password selector) + (recovery-person signature)
+ (m-of-n threshold). Biometric-match assurance lives with the enclave (device tiers) or the
human (this tier), not with a stored template here.
"""

import pytest

from atlas.crypto import shamir
from atlas.crypto.primitives import H, random_bytes
from atlas.keys.hardware_key import HighStakesRequest, YubiKeyBio
from atlas.recovery import oprf
from atlas.keys.identity import build_identity_tree
from atlas.realid.recovery_anchor import (
    DeviceCapability,
    EnrolmentRefused,
    RecordNotFound,
    RecoveryAnchorError,
    RecoveryPersonRequired,
    ThresholdNotMet,
    agent_binding_request,
    enrol_recovery_anchor,
    recover_total_loss,
    recovery_selector,
)

NAME = "John Q. Smith"
PASSWORD = "correct horse battery staple"
# The recovery servers' OPRF key, sharded (n-of-n). In deployment each shard lives on a
# separate server; a password guess needs an online evaluation against them (no offline grind).
OPRF_SHARDS = [oprf.OPRFShard(s) for s in oprf.split_key(oprf.keygen(), 3)]
SE_PHONE = DeviceCapability(has_secure_element=True, has_liveness=True)
SE_ONLY = DeviceCapability(has_secure_element=True, has_liveness=False)  # plain computer
NO_SE = DeviceCapability(has_secure_element=False)


def _agent():
    """The recovery person: a live human with their own Atlas credential. Their
    fingerprint-gated signature IS the in-person attestation."""
    return YubiKeyBio()


def _sign(agent, pseudonym, challenge):
    req = HighStakesRequest(action="recover", context=pseudonym, challenge=challenge)
    return agent.authorize(req, fingerprint_matched=True)


def _bind(agent, pseudonym):
    """The recovery person's DETERMINISTIC binding signature — becomes key material (B2)."""
    return agent.authorize(agent_binding_request(pseudonym), fingerprint_matched=True)


def _enrol(system_id_seed, agent, *, n=3, k=2, device=SE_PHONE, name=NAME, oprf_shards=None):
    pseudonym = recovery_selector(name, PASSWORD, oprf_shards=oprf_shards)
    return enrol_recovery_anchor(legal_name=name, password=PASSWORD,
                                 system_id_seed=system_id_seed, agent_public=agent.public,
                                 agent_binding_signature=_bind(agent, pseudonym),
                                 device=device, n=n, k=k, oprf_shards=oprf_shards)


# --------------------------------------------------------------------------- happy path
def test_total_loss_recovery_restores_the_system_id():
    # The digital you IS the System-ID, derived from the TSK. We seal that material and
    # prove recovery restores the SAME System-ID (its public handle regenerates from it).
    tsk_seed = random_bytes(32)
    tree = build_identity_tree(tsk_seed)
    system_id_seed = tree._system_id_secret          # System-ID (derived from TSK)
    agent = _agent()
    record, shares = _enrol(system_id_seed, agent)
    challenge = random_bytes(16)

    recovered = recover_total_loss(
        record, legal_name=NAME, password=PASSWORD,
        server_shares=shares[:2], recovery_challenge=challenge,
        agent_signature=_sign(agent, record.recovery_pseudonym, challenge),
        agent_binding_signature=_bind(agent, record.recovery_pseudonym),
        device=SE_ONLY,   # a plain SE computer — the recovery person is the liveness
    )
    assert recovered == system_id_seed
    # the recovered material reconstitutes the SAME System-ID (its public handle).
    assert H(b"atlas/system-id-handle", recovered) == tree.system_id_handle()


# --------------------------------------------------------------------------- privacy
def test_recovery_pseudonym_is_unlinked_to_the_digital_you():
    # The selector is a pure function of (name, password), INDEPENDENT of the digital
    # seed: enrolling two different digital identities under the same name+password yields
    # the SAME recovery pseudonym -> it carries no information about the digital you.
    agent = _agent()
    r1, _ = _enrol(random_bytes(32), agent)
    r2, _ = _enrol(random_bytes(32), agent)
    assert r1.recovery_pseudonym == r2.recovery_pseudonym == recovery_selector(NAME, PASSWORD)
    # ...and neither pseudonym equals (or is derivable from) either System-ID root.


def test_server_record_is_opaque_without_the_ceremony():
    digital_seed = random_bytes(32)
    record, _shares = _enrol(digital_seed, _agent())
    # The stored bridge is ciphertext — the digital seed is nowhere in the record.
    assert digital_seed not in record.sealed_bridge
    assert record.sealed_bridge != digital_seed


def test_record_holds_no_biometric_material():
    # #6: the record has no biometric field at all — nothing to leak on breach.
    record, _shares = _enrol(random_bytes(32), _agent())
    assert not hasattr(record, "helper")
    assert set(vars(record)) == {"recovery_pseudonym", "sealed_bridge", "agent_public", "n", "k"}


def test_record_never_stores_the_binding_signature():
    # B2 hardening: the recovery person's DETERMINISTIC binding signature becomes bridge-key
    # material, so persisting it next to the record would decay the live-human AND-factor into a
    # static secret that a store-breach attacker could replay (name+password+k shares, no person).
    # Lock in permanently that the exact signature bytes appear NOWHERE in the record — not as a
    # field, and not folded into the sealed bridge. (_bind is deterministic, so this is the very
    # value enrolment used as key material.)
    agent = _agent()
    binding_sig = _bind(agent, recovery_selector(NAME, PASSWORD))
    record, _shares = _enrol(random_bytes(32), agent)
    assert "agent_binding_signature" not in vars(record)
    for value in vars(record).values():
        if isinstance(value, (bytes, bytearray)):
            assert binding_sig not in value      # not a field and not embedded in the ciphertext


# --------------------------------------------------------------------------- fail-closed rungs
def test_wrong_password_finds_no_record():
    agent = _agent()
    record, shares = _enrol(random_bytes(32), agent)
    challenge = random_bytes(16)
    with pytest.raises(RecordNotFound):
        recover_total_loss(record, legal_name=NAME, password="wrong password",
                           server_shares=shares[:2], recovery_challenge=challenge,
                           agent_signature=_sign(agent, record.recovery_pseudonym, challenge),
                           agent_binding_signature=_bind(agent, record.recovery_pseudonym),
                           device=SE_PHONE)


def test_missing_recovery_person_fails_closed():
    record, shares = _enrol(random_bytes(32), _agent())
    with pytest.raises(RecoveryPersonRequired):
        recover_total_loss(record, legal_name=NAME, password=PASSWORD,
                           server_shares=shares[:2], recovery_challenge=random_bytes(16),
                           agent_signature=b"\x00" * 64,
                           agent_binding_signature=b"\x00" * 64, device=SE_PHONE)


def test_forged_recovery_person_key_fails_closed():
    record, shares = _enrol(random_bytes(32), _agent())
    impostor = _agent()               # a different human, not the registered agent
    challenge = random_bytes(16)
    with pytest.raises(RecoveryPersonRequired):
        recover_total_loss(record, legal_name=NAME, password=PASSWORD,
                           server_shares=shares[:2], recovery_challenge=challenge,
                           agent_signature=_sign(impostor, record.recovery_pseudonym, challenge),
                           agent_binding_signature=_bind(impostor, record.recovery_pseudonym),
                           device=SE_PHONE)


def test_replayed_recovery_person_signature_fails_closed():
    agent = _agent()
    record, shares = _enrol(random_bytes(32), agent)
    old = _sign(agent, record.recovery_pseudonym, random_bytes(16))   # for a stale challenge
    with pytest.raises(RecoveryPersonRequired):
        recover_total_loss(record, legal_name=NAME, password=PASSWORD,
                           server_shares=shares[:2], recovery_challenge=random_bytes(16),
                           agent_signature=old,
                           agent_binding_signature=_bind(agent, record.recovery_pseudonym),
                           device=SE_PHONE)       # replay against a new one


def test_below_threshold_servers_fails_closed():
    agent = _agent()
    record, shares = _enrol(random_bytes(32), agent, n=3, k=2)
    challenge = random_bytes(16)
    with pytest.raises(ThresholdNotMet):
        recover_total_loss(record, legal_name=NAME, password=PASSWORD,
                           server_shares=shares[:1], recovery_challenge=challenge,
                           agent_signature=_sign(agent, record.recovery_pseudonym, challenge),
                           agent_binding_signature=_bind(agent, record.recovery_pseudonym),
                           device=SE_PHONE)


def test_server_collusion_without_human_is_inert():
    # The strongest server attacker: holds the record AND all n shares. Without the live
    # recovery person's attestation it still gets nothing (server access != authorization).
    record, shares = _enrol(random_bytes(32), _agent(), n=3, k=2)
    with pytest.raises(RecoveryPersonRequired):
        recover_total_loss(record, legal_name=NAME, password=PASSWORD,
                           server_shares=shares, recovery_challenge=random_bytes(16),
                           agent_signature=b"\x00" * 64,
                           agent_binding_signature=b"\x00" * 64, device=SE_PHONE)


def test_oprf_hardened_recovery_round_trip_and_requires_the_servers():
    # B3: with the OPRF wired, enrol+recover succeed WITH the servers' shards; an attacker who
    # holds the record but not the servers cannot even resolve the selector to the record.
    seed = random_bytes(32)
    agent = _agent()
    record, shares = _enrol(seed, agent, oprf_shards=OPRF_SHARDS)
    challenge = random_bytes(16)
    assert recover_total_loss(
        record, legal_name=NAME, password=PASSWORD, server_shares=shares[:2],
        recovery_challenge=challenge,
        agent_signature=_sign(agent, record.recovery_pseudonym, challenge),
        agent_binding_signature=_bind(agent, record.recovery_pseudonym),
        device=SE_ONLY, oprf_shards=OPRF_SHARDS) == seed
    # WITHOUT the servers' OPRF key the selector no longer resolves the record (fail-closed)
    with pytest.raises(RecordNotFound):
        recover_total_loss(
            record, legal_name=NAME, password=PASSWORD, server_shares=shares[:2],
            recovery_challenge=challenge,
            agent_signature=_sign(agent, record.recovery_pseudonym, challenge),
            agent_binding_signature=_bind(agent, record.recovery_pseudonym),
            device=SE_ONLY)          # no oprf_shards -> scrypt-only selector != the record's


def test_selector_offline_enumeration_needs_the_oprf_servers():
    # B3: the selector depends on the servers' OPRF key, so a record thief cannot recompute it
    # from (name, password) alone — scrypt-only AND a different server key both diverge — hence
    # no offline grind. The correct servers reproduce it deterministically.
    sel = recovery_selector(NAME, PASSWORD, oprf_shards=OPRF_SHARDS)
    assert recovery_selector(NAME, PASSWORD) != sel                          # scrypt-only can't
    other = [oprf.OPRFShard(s) for s in oprf.split_key(oprf.keygen(), 3)]
    assert recovery_selector(NAME, PASSWORD, oprf_shards=other) != sel       # wrong servers can't
    assert recovery_selector(NAME, PASSWORD, oprf_shards=OPRF_SHARDS) == sel  # right servers: deterministic


def test_recovery_person_is_a_cryptographic_factor_not_just_a_check():
    # B2: the recovery person's key is mixed INTO the bridge key, not merely checked. Even with
    # the correct name+password, k server shares, AND a valid FRESH attestation from the real
    # person, a binding contribution from a DIFFERENT key cannot form the seal -> fail-closed.
    seed = random_bytes(32)
    agent, impostor = _agent(), _agent()
    record, shares = _enrol(seed, agent)
    challenge = random_bytes(16)
    with pytest.raises(RecoveryPersonRequired):
        recover_total_loss(
            record, legal_name=NAME, password=PASSWORD, server_shares=shares[:2],
            recovery_challenge=challenge,
            agent_signature=_sign(agent, record.recovery_pseudonym, challenge),      # real fresh sig
            agent_binding_signature=_bind(impostor, record.recovery_pseudonym),      # WRONG key's binding
            device=SE_ONLY)
    # the genuine person's binding recovers it
    assert recover_total_loss(
        record, legal_name=NAME, password=PASSWORD, server_shares=shares[:2],
        recovery_challenge=challenge,
        agent_signature=_sign(agent, record.recovery_pseudonym, challenge),
        agent_binding_signature=_bind(agent, record.recovery_pseudonym),
        device=SE_ONLY) == seed


# --------------------------------------------------------------------------- device model
def test_enrol_requires_secure_element():
    with pytest.raises(EnrolmentRefused):
        _enrol(random_bytes(32), _agent(), device=NO_SE)


def test_recovery_terminal_requires_secure_element():
    agent = _agent()
    record, shares = _enrol(random_bytes(32), agent)
    challenge = random_bytes(16)
    with pytest.raises(EnrolmentRefused):
        recover_total_loss(record, legal_name=NAME, password=PASSWORD,
                           server_shares=shares[:2], recovery_challenge=challenge,
                           agent_signature=_sign(agent, record.recovery_pseudonym, challenge),
                           agent_binding_signature=_bind(agent, record.recovery_pseudonym),
                           device=NO_SE)


def test_name_is_the_username_password_differentiates_namesakes():
    # Two different people who share a name are told apart ONLY by their password ->
    # distinct records. A different name is a different record regardless of password.
    # And it's deterministic (a direct 1:1 lookup, never a scan) — regenerable from memory.
    smith_a = recovery_selector("John Smith", "password-A")
    smith_b = recovery_selector("John Smith", "password-B")
    jones = recovery_selector("Mary Jones", "password-A")
    assert smith_a != smith_b       # same name, different password -> different record
    assert smith_a != jones         # different name -> different record
    assert recovery_selector("john  smith ", "password-A") == smith_a   # normalized + stable
