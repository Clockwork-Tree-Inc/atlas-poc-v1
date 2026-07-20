"""Credential anonymity, PQC posture & re-rooting — adversarial tests (§7.2).

Test/dummy data only. Covers: BBS rides inside the PQC tunnel; crypto-agility
swap seam; System-ID re-root forward-heals; holder-authority (no operator path);
TSK rotation requires the full parameter set; non-custody of pseudonyms.
"""

import os

import pytest

from atlas.crypto import kem
from atlas.keys.identity import build_identity_tree
from atlas.realid import (
    AssuranceLevel, BBSCredentialScheme, FullRecoveryParams, MockCredentialScheme,
    OperatorForbidden, RerootError, open_presentation, reroot_system_id, rotate_tsk,
    seal_presentation, ml_dsa_authenticity_sign, ml_dsa_authenticity_verify,
)
from atlas.realid.storage import SplitStore as _SplitStore, assert_non_custody


def _tree():
    return build_identity_tree(os.urandom(32))


# §2 / §7.2 — BBS proof rides INSIDE the PQC tunnel; not observable without keys
def test_bbs_presentation_shielded_by_pqc_tunnel():
    scheme = BBSCredentialScheme()
    tree = _tree()
    _, cred = scheme.issue(tree.system_id_handle(), AssuranceLevel.L1)
    proof = scheme.present(cred, nonce=b"verifier-chal")

    verifier_kem = kem.generate_keypair()          # authorized verifier's KEM keypair
    sealed = seal_presentation(proof, verifier_kem.public)

    # passive observer sees ONLY PQC ciphertext — the BBS proof is not present
    assert proof.proof not in sealed.ciphertext
    assert b"atlas-verified" not in sealed.ciphertext
    # an observer without the verifier's KEM secret cannot open it
    with pytest.raises(Exception):
        open_presentation(sealed, kem.generate_keypair())
    # the authorized verifier (holds the KEM secret) recovers the proof and verifies
    recovered = open_presentation(sealed, verifier_kem)
    assert scheme.verify(scheme.verifier_key, recovered, required=AssuranceLevel.L1)


# §3 / §7.2 — crypto-agility: the same tree-level flow runs over ANY scheme
def test_agility_swap_scheme_without_changing_calling_code():
    tree = _tree()

    def flow(scheme):
        # identical calling code regardless of the underlying scheme
        _, cred = scheme.issue(tree.system_id_handle(), AssuranceLevel.L1)
        proof = scheme.present(cred, nonce=b"n")
        return scheme.verify(scheme.verifier_key, proof, required=AssuranceLevel.L1)

    assert flow(BBSCredentialScheme())     # real BBS+
    assert flow(MockCredentialScheme())    # drop-in alternate, no calling-code change


def test_optional_ml_dsa_hybrid_authenticity_is_pq():
    from atlas.crypto.sign import generate_sig_keypair
    kp = generate_sig_keypair()
    sig = ml_dsa_authenticity_sign(kp, level=AssuranceLevel.L1, context=b"ctx")
    assert ml_dsa_authenticity_verify(kp.public, level=AssuranceLevel.L1, context=b"ctx", signature=sig)
    # authenticity is PQ (ML-DSA); it does NOT make the anonymity PQ — different claim
    assert not ml_dsa_authenticity_verify(kp.public, level=AssuranceLevel.L2, context=b"ctx", signature=sig)


# §5 / §7.2 — re-rooting forward-heals; old never yields the real identity
def test_reroot_forward_heals_and_keeps_durable_tsk():
    tree = _tree()
    old = {tree.child(c).handle for c in tree.children}
    new_tree = reroot_system_id(tree, user_authorized=True)
    new = {new_tree.child(c).handle for c in new_tree.children}
    # new pseudonyms are unlinkable from the old set
    assert old.isdisjoint(new)
    assert new_tree.system_id_handle() != tree.system_id_handle()
    # the TSK (durable root) is unchanged across the re-root
    assert new_tree.root_handle == tree.root_handle
    assert new_tree.rotation == tree.rotation + 1
    # the System-ID is blind: the (rotated) handle is not the real identity — it is
    # a hash of a blind secret, carrying no real-world id.
    assert new_tree.system_id_handle() != new_tree.tsk_seed


# §5 / §7.2 — holder-authority: no operator path can re-root a user
def test_holder_authority_no_operator_reroot():
    tree = _tree()
    with pytest.raises(OperatorForbidden):
        reroot_system_id(tree, user_authorized=False)


# §5.1 / §7.2 — TSK rotation requires the COMPLETE full-recovery parameter set
def test_tsk_rotation_requires_full_recovery_params():
    full = FullRecoveryParams(in_person=True, live_uncoerced_biometric=True,
                              threshold_shares_met=True, held_fuzz=True)
    rotated = rotate_tsk(new_tsk_seed=os.urandom(32), params=full, user_authorized=True)
    assert rotated.rotation == 0
    # any missing parameter blocks it
    for missing in ["in_person", "live_uncoerced_biometric", "threshold_shares_met", "held_fuzz"]:
        kwargs = dict(in_person=True, live_uncoerced_biometric=True,
                      threshold_shares_met=True, held_fuzz=True)
        kwargs[missing] = False
        with pytest.raises(RerootError):
            rotate_tsk(new_tsk_seed=os.urandom(32), params=FullRecoveryParams(**kwargs), user_authorized=True)
    # and no operator path
    with pytest.raises(OperatorForbidden):
        rotate_tsk(new_tsk_seed=os.urandom(32), params=full, user_authorized=False)


# §4 / §7.2 — non-custody: no single non-device store reconstructs the System-ID
def test_pseudonym_system_id_non_custodial():
    tree = _tree()
    sid_material = tree.system_id_handle()         # the value stored non-custodially
    split = _SplitStore.split(sid_material)
    assert split.reconstruct_on_device(user_share=split.user_share) == sid_material
    # the server holds at most one share + status -> not reconstructable
    assert_non_custody({"status": "verified", "share": split.server_holds()})
