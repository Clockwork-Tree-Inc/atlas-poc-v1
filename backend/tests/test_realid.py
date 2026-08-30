"""Real-ID / unlinkability / duress — adversarial tests (Real-ID spec §8.2).

TEST/DUMMY identity data only (Real-ID spec §0). Asserts the partitioning,
inheritance-privacy, non-custody, unlinkability (T-20), uniqueness, duress (T-7),
and two-modes properties the showcase must demonstrate.
"""

import os
import random

import pytest

from atlas.keys.identity import build_identity_tree
from atlas.realid import (
    AssuranceLevel, AtlasVerificationAuthority, DPCounter, DuressEnrolment,
    NonCustodyError, OnDeviceStore, RealIDVault, SplitStore, ConsentRequired,
    atlas_as_identity, authenticate, bind_to_external, epoch_pseudonym,
)
from atlas.realid.realid_child import _child_secret
from atlas.realid.storage import assert_non_custody

# A fabricated, obviously-fake stand-in identity record (NOT real PII).
DUMMY_ID = b'{"name":"Jane Q. Test","gov_id":"TEST-0000-FAKE","dob":"2000-01-01"}'


def _tree():
    return build_identity_tree(os.urandom(32))


# §8.2 partitioning — non-real-ID children cannot read/derive the real-ID material
def test_partitioning_only_realid_child_can_read():
    tree = _tree()
    vault = RealIDVault(tree.child("real-id"))
    vault.bind(DUMMY_ID)
    assert vault.surface_legal_identity(consent=True, context="finance") == DUMMY_ID
    # a sibling child's secret cannot decrypt the real-ID blob (isolation)
    for sibling in ("anonymous", "authorship", "recovery"):
        sib_store = OnDeviceStore(_child_secret(tree.child(sibling)))
        sib_store._blob = vault.raw_blob_for_isolation_test
        with pytest.raises(Exception):
            sib_store.surface()


def test_realid_vault_must_be_realid_child():
    tree = _tree()
    with pytest.raises(ValueError):
        RealIDVault(tree.child("authorship"))


# §8.2 inheritance privacy — BBS+ proof reveals neither ID, System-ID, nor link
def test_inheritance_proof_reveals_nothing_and_sibling_isolated():
    tree = _tree()
    authority = AtlasVerificationAuthority()
    record, cred = authority.verify_and_issue(tree.system_id_handle(), AssuranceLevel.L1)
    # backend record is STATUS only — no ID
    assert record.level == AssuranceLevel.L1 and DUMMY_ID not in repr(record).encode()
    # two children each present an UNLINKABLE BBS+ proof; a verifier accepts both...
    pa = authority.present(cred, nonce=b"chal-a")
    pb = authority.present(cred, nonce=b"chal-b")
    assert AtlasVerificationAuthority.verify_proof(authority.bbs_key, pa, required=AssuranceLevel.L1)
    assert AtlasVerificationAuthority.verify_proof(authority.bbs_key, pb, required=AssuranceLevel.L1)
    # ...the System-ID is HIDDEN: not recoverable from the proof, not in revealed,
    # and the two re-randomized proofs are not equal (unlinkable).
    sid = tree.system_id_handle()
    assert authority.resolve_system_id(pa) is None
    assert sid.hex() not in "".join(pa.revealed)
    assert sid not in pa.proof and pa.proof != pb.proof


def test_level_gate_rejects_insufficient_assurance():
    tree = _tree()
    authority = AtlasVerificationAuthority()
    _, cred = authority.verify_and_issue(tree.system_id_handle(), AssuranceLevel.L0)
    proof = authority.present(cred, nonce=b"n")
    # an L0 proof cannot satisfy a context requiring L1
    assert not AtlasVerificationAuthority.verify_proof(authority.bbs_key, proof, required=AssuranceLevel.L1)


def test_level_gate_cannot_be_bypassed_by_forging_the_level_field():
    """Regression (security review): the gate must use the BBS-REVEALED level,
    not the unauthenticated InheritedProof.level field. A genuine L0 credential
    with .level forged to L2 must NOT clear an L2 gate."""
    from atlas.realid.verification import InheritedProof
    tree = _tree()
    authority = AtlasVerificationAuthority()
    _, cred0 = authority.verify_and_issue(tree.system_id_handle(), AssuranceLevel.L0)
    honest = authority.present(cred0, nonce=b"n")
    forged = InheritedProof(proof=honest.proof, revealed=honest.revealed, nonce=honest.nonce,
                            level=AssuranceLevel.L2, discloses_system_id=False)
    assert not AtlasVerificationAuthority.verify_proof(authority.bbs_key, forged, required=AssuranceLevel.L2)
    # and a genuine L2 credential still works
    _, cred2 = authority.verify_and_issue(tree.system_id_handle(), AssuranceLevel.L2)
    assert AtlasVerificationAuthority.verify_proof(authority.bbs_key, authority.present(cred2, nonce=b"n"),
                                                   required=AssuranceLevel.L2)


# §8.2 accountability — holder discloses the System-ID ONLY under cause
def test_accountable_resolution_only_under_cause():
    tree = _tree()
    authority = AtlasVerificationAuthority()
    _, cred = authority.verify_and_issue(tree.system_id_handle(), AssuranceLevel.L1)
    # normal presentation hides the System-ID (unlinkable)
    normal = authority.present(cred, nonce=b"n1")
    assert authority.resolve_system_id(normal) is None
    # under cause, the holder produces a full-disclosure proof revealing it
    disclosure = authority.present(cred, nonce=b"n2", disclose_system_id=True)
    assert AtlasVerificationAuthority.verify_proof(authority.bbs_key, disclosure, required=AssuranceLevel.L1)
    assert authority.resolve_system_id(disclosure) == tree.system_id_handle()


# §8.2 non-custody — no single non-device store can reconstruct the ID
def test_non_custody_split_store():
    split = SplitStore.split(DUMMY_ID)
    # on-device reconstruction (device + user share) works
    assert split.reconstruct_on_device(user_share=split.user_share) == DUMMY_ID
    # the server holds exactly one share — not reconstructable
    server = {"status": "verified", "share": split.server_holds()}
    assert_non_custody(server)            # one share + status -> ok
    # two shares at the server would be custodial -> rejected
    with pytest.raises(NonCustodyError):
        assert_non_custody({"a": split.device_share, "b": split.cloud_share})


def test_on_device_store_never_plaintext():
    tree = _tree()
    store = OnDeviceStore(_child_secret(tree.child("real-id")))
    store.store(DUMMY_ID)
    assert DUMMY_ID not in store._blob       # encrypted at rest


# §6 / T-20 — per-epoch unlinkability
def test_per_epoch_pseudonyms_unlinkable_but_rooted():
    tree = _tree()
    child = tree.child("anonymous")
    e1, e2 = (1).to_bytes(8, "big"), (2).to_bytes(8, "big")
    p1, p2 = epoch_pseudonym(child, e1), epoch_pseudonym(child, e2)
    assert p1 != p2                          # rotates each epoch
    assert epoch_pseudonym(child, e1) == p1  # stable within an epoch
    # an observer cannot derive the child/System-ID from a pseudonym (one-way)
    assert child.handle not in p1 and tree.system_id_handle() not in p1
    # a different child gives different pseudonyms (no cross-child collision)
    assert epoch_pseudonym(tree.child("authorship"), e1) != p1


def test_dp_bounds_side_channel_counts():
    dp = DPCounter(epsilon=0.5)
    rng = random.Random(7)
    # released values are noised (rarely exactly the true count), so per-epoch
    # activity counts don't trivially correlate.
    released = [dp.release(10, rng=rng) for _ in range(5)]
    assert any(abs(r - 10) > 1e-9 for r in released)


# §8.2 two modes — same live-human primitive; Mode 1 stores no external identity
def test_mode1_bind_to_external_stores_nothing():
    tree = _tree()
    authority = AtlasVerificationAuthority()
    _, cred = authority.verify_and_issue(tree.system_id_handle(), AssuranceLevel.L1)
    proof = authority.present(cred, nonce=b"svc-nonce")
    binding = bind_to_external(bbs_key=authority.bbs_key, proof=proof,
                               required=AssuranceLevel.L1, mock_service="mock-facebook")
    assert binding.atlas_stored_external_identity is False


def test_mode2_atlas_as_identity_requires_consent_and_logs():
    tree = _tree()
    vault = RealIDVault(tree.child("real-id"))
    vault.bind(DUMMY_ID)
    # no consent -> refused
    with pytest.raises(ConsentRequired):
        atlas_as_identity(vault=vault, consent=False, context="legal-contract")
    res = atlas_as_identity(vault=vault, consent=True, context="legal-contract")
    assert res.surfaced_test_id == DUMMY_ID and res.level == AssuranceLevel.L2
    assert vault.log.events and vault.log.events[-1]["context"] == "legal-contract"


# §7 / T-7 — duress channel: externally indistinguishable, internally withholds
def test_duress_externally_indistinguishable_internally_withholds():
    enr = DuressEnrolment.enrol(normal_pattern=b"tap-tap-hold", duress_pattern=b"tap-hold-tap", canary_finger=3)
    normal = authenticate(enr, pattern=b"tap-tap-hold", finger=1)
    duress = authenticate(enr, pattern=b"tap-hold-tap", finger=1)
    canary = authenticate(enr, pattern=b"tap-tap-hold", finger=3)   # canary finger
    # observer sees identical success on all three
    assert normal.surface_success == duress.surface_success == canary.surface_success is True
    # internally: duress flagged + sensitive action withheld
    assert not normal.duress and normal.sensitive_action_allowed
    assert duress.duress and not duress.sensitive_action_allowed
    assert canary.duress and not canary.sensitive_action_allowed
    # a genuinely wrong pattern is an ordinary failure (distinct from duress)
    wrong = authenticate(enr, pattern=b"nope", finger=1)
    assert not wrong.surface_success and not wrong.duress


# §6 — uniqueness preserved: pseudonyms still root to one verified System-ID
def test_uniqueness_one_human_one_root():
    tree = _tree()
    authority = AtlasVerificationAuthority()
    sid = tree.system_id_handle()
    authority.verify_and_issue(sid, AssuranceLevel.L1)
    assert authority.is_unique_root(sid)
    # re-verification of the same root does not create a second identity
    authority.verify_and_issue(sid, AssuranceLevel.L1)
    assert len(authority._verified_roots) == 1
