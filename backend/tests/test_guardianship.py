"""Adversarial tests for guardianship (TRUST_LAYER.md #4/#5).

Properties:
  * configurable m-of-n round-trip through the guardian set;
  * ANTI-COLLUSION invariant (#4): a policy whose institutional guardians >= m is REJECTED at
    construction; and a presented share set that is all-institutional is rejected at
    reconstruction (defence-in-depth) — servers/operators alone can never recover you;
  * WITTING veto aborts; WITTING approval threshold enforced; forged approvals/vetoes from
    non-witting (or unknown) labels are ignored;
  * below-threshold and wrong-factor remain fail-closed (delegated to threshold_seal).
"""

import pytest

from atlas.crypto.sign import generate_sig_keypair, sign
from atlas.recovery import threshold_seal as ts
from atlas.recovery.guardianship import (
    ApprovalsNotMet,
    CardRequired,
    Guardian,
    GuardianKind,
    GuardianshipError,
    GuardianshipPolicy,
    InstitutionalThresholdError,
    WittingVeto,
    card_recovery_message,
    reconstruct_under_guardianship,
    rotate_guardianship,
    seal_under_guardianship,
)

SECRET = b"recovery-secret-under-guardianship"
USER_HALF = b"U" * 32          # a full-entropy 32-byte user half (TSK-bound)


def _g(label, kind=GuardianKind.SILENT, institutional=False):
    return Guardian(custodian=ts.Custodian(label=label, institutional=institutional), kind=kind)


def _mixed_set():
    # 2 personal silent + 1 witting human + 2 institutional operators; m=3 => institutional(2) < 3
    return (
        _g("home-node"),
        _g("laptop"),
        _g("spouse", kind=GuardianKind.WITTING),
        _g("op-eu", institutional=True),
        _g("op-us", institutional=True),
    )


# --------------------------------------------------------------------------- round-trip
def test_round_trip():
    policy = GuardianshipPolicy(guardians=_mixed_set(), m=3)
    sealed, shares = seal_under_guardianship(SECRET, user_half=USER_HALF, policy=policy,
                                             storage=ts.StorageLocation.GUARDIANS, context=b"ctx")
    # a non-institutional-inclusive 3-subset opens it
    got = reconstruct_under_guardianship(
        sealed, user_half=USER_HALF, policy=policy,
        presented_shares=[shares[0], shares[1], shares[3]])  # home, laptop, op-eu
    assert got == SECRET


# --------------------------------------------------------------------------- anti-collusion
def test_policy_rejects_institutional_majority_reaching_threshold():
    # 3 institutional with m=3 => an all-institutional subset could recover -> rejected.
    guardians = (_g("op-eu", institutional=True), _g("op-us", institutional=True),
                 _g("op-asia", institutional=True), _g("home-node"))
    with pytest.raises(InstitutionalThresholdError):
        GuardianshipPolicy(guardians=guardians, m=3)


def test_policy_accepts_institutional_below_threshold():
    # 2 institutional with m=3 is fine (institutional_count < m).
    GuardianshipPolicy(guardians=_mixed_set(), m=3)  # must not raise


def test_reconstruction_rejects_all_institutional_presented_set():
    # Even if callers gather an all-institutional set that numerically meets m, refuse it.
    guardians = (_g("op-eu", institutional=True), _g("op-us", institutional=True),
                 _g("op-asia", institutional=True), _g("home-node"), _g("laptop"))
    # institutional(3) < m(4), so the policy is valid; the all-institutional set is caught
    # defensively at reconstruction instead.
    policy = GuardianshipPolicy(guardians=guardians, m=4)
    sealed, shares = seal_under_guardianship(SECRET, user_half=USER_HALF, policy=policy,
                                             storage=ts.StorageLocation.SERVER_SHARDED)
    # the 3 institutional shares alone (all-institutional) -> rejected before threshold math
    with pytest.raises(InstitutionalThresholdError):
        reconstruct_under_guardianship(sealed, user_half=USER_HALF, policy=policy,
                                       presented_shares=[shares[0], shares[1], shares[2]])


# --------------------------------------------------------------------------- witting gate
def test_witting_veto_aborts():
    policy = GuardianshipPolicy(guardians=_mixed_set(), m=3)
    sealed, shares = seal_under_guardianship(SECRET, user_half=USER_HALF, policy=policy,
                                             storage=ts.StorageLocation.GUARDIANS)
    with pytest.raises(WittingVeto):
        reconstruct_under_guardianship(
            sealed, user_half=USER_HALF, policy=policy,
            presented_shares=[shares[0], shares[1], shares[3]],
            witting_vetoes=["spouse"])


def test_min_witting_approvals_enforced():
    policy = GuardianshipPolicy(guardians=_mixed_set(), m=3, min_witting_approvals=1)
    sealed, shares = seal_under_guardianship(SECRET, user_half=USER_HALF, policy=policy,
                                             storage=ts.StorageLocation.GUARDIANS)
    subset = [shares[0], shares[1], shares[3]]
    with pytest.raises(ApprovalsNotMet):
        reconstruct_under_guardianship(sealed, user_half=USER_HALF, policy=policy,
                                       presented_shares=subset)  # no approvals
    # with the witting approval it opens
    assert reconstruct_under_guardianship(
        sealed, user_half=USER_HALF, policy=policy, presented_shares=subset,
        witting_approvals=["spouse"]) == SECRET


def test_forged_approval_from_unknown_label_ignored():
    policy = GuardianshipPolicy(guardians=_mixed_set(), m=3, min_witting_approvals=1)
    sealed, shares = seal_under_guardianship(SECRET, user_half=USER_HALF, policy=policy,
                                             storage=ts.StorageLocation.GUARDIANS)
    subset = [shares[0], shares[1], shares[3]]
    with pytest.raises(ApprovalsNotMet):
        # "attacker" is not a witting guardian -> not counted
        reconstruct_under_guardianship(sealed, user_half=USER_HALF, policy=policy,
                                       presented_shares=subset, witting_approvals=["attacker"])


def test_veto_from_non_witting_label_ignored():
    # a silent/unknown label cannot veto; only real witting guardians can.
    policy = GuardianshipPolicy(guardians=_mixed_set(), m=3)
    sealed, shares = seal_under_guardianship(SECRET, user_half=USER_HALF, policy=policy,
                                             storage=ts.StorageLocation.GUARDIANS)
    assert reconstruct_under_guardianship(
        sealed, user_half=USER_HALF, policy=policy,
        presented_shares=[shares[0], shares[1], shares[3]],
        witting_vetoes=["home-node", "outsider"]) == SECRET  # neither is witting


# --------------------------------------------------------------------------- fail-closed
def test_below_threshold_fails():
    policy = GuardianshipPolicy(guardians=_mixed_set(), m=3)
    sealed, shares = seal_under_guardianship(SECRET, user_half=USER_HALF, policy=policy,
                                             storage=ts.StorageLocation.GUARDIANS)
    with pytest.raises(ts.ThresholdNotMet):
        reconstruct_under_guardianship(sealed, user_half=USER_HALF, policy=policy,
                                       presented_shares=[shares[0], shares[3]])  # only 2


def test_wrong_user_half_fails():
    policy = GuardianshipPolicy(guardians=_mixed_set(), m=3)
    sealed, shares = seal_under_guardianship(SECRET, user_half=USER_HALF, policy=policy,
                                             storage=ts.StorageLocation.GUARDIANS)
    with pytest.raises(ts.UnsealFailed):
        reconstruct_under_guardianship(sealed, user_half=b"wrong", policy=policy,
                                       presented_shares=[shares[0], shares[1], shares[3]])


def test_min_approvals_cannot_exceed_witting_count():
    # policy sanity: can't require more approvals than there are witting guardians.
    with pytest.raises(GuardianshipError):
        GuardianshipPolicy(guardians=_mixed_set(), m=3, min_witting_approvals=2)  # only 1 witting


# ------------------------------------------------- user's-choice card requirement (BINDING)
def test_require_card_needs_card_pub():
    with pytest.raises(GuardianshipError):
        GuardianshipPolicy(guardians=_mixed_set(), m=3, require_card=True)  # no card_pub


def test_card_required_blocks_guardian_recovery_without_the_card():
    # The card requirement is enforced HERE (execution), not just in the tier selector: a full
    # guardian quorum + the right user half cannot reopen the sketch without a card signature.
    card = generate_sig_keypair()
    policy = GuardianshipPolicy(guardians=_mixed_set(), m=3, require_card=True, card_pub=card.public)
    sealed, shares = seal_under_guardianship(SECRET, user_half=USER_HALF, policy=policy,
                                             storage=ts.StorageLocation.GUARDIANS, context=b"ctx")
    subset = [shares[0], shares[1], shares[3]]
    with pytest.raises(CardRequired):
        reconstruct_under_guardianship(sealed, user_half=USER_HALF, policy=policy,
                                       presented_shares=subset)  # no card signature


def test_card_required_opens_with_a_valid_card_signature():
    card = generate_sig_keypair()
    policy = GuardianshipPolicy(guardians=_mixed_set(), m=3, require_card=True, card_pub=card.public)
    sealed, shares = seal_under_guardianship(SECRET, user_half=USER_HALF, policy=policy,
                                             storage=ts.StorageLocation.GUARDIANS, context=b"ctx")
    card_sig = sign(card, card_recovery_message(sealed.context))
    got = reconstruct_under_guardianship(sealed, user_half=USER_HALF, policy=policy,
                                         presented_shares=[shares[0], shares[1], shares[3]],
                                         card_signature=card_sig)
    assert got == SECRET


def test_card_required_rejects_a_wrong_card_signature():
    card, imposter = generate_sig_keypair(), generate_sig_keypair()
    policy = GuardianshipPolicy(guardians=_mixed_set(), m=3, require_card=True, card_pub=card.public)
    sealed, shares = seal_under_guardianship(SECRET, user_half=USER_HALF, policy=policy,
                                             storage=ts.StorageLocation.GUARDIANS, context=b"ctx")
    bad_sig = sign(imposter, card_recovery_message(sealed.context))  # not the card
    with pytest.raises(CardRequired):
        reconstruct_under_guardianship(sealed, user_half=USER_HALF, policy=policy,
                                       presented_shares=[shares[0], shares[1], shares[3]],
                                       card_signature=bad_sig)


def test_no_card_policy_is_unchanged():
    # default (require_card=False): guardian recovery opens with no card signature (design of record).
    policy = GuardianshipPolicy(guardians=_mixed_set(), m=3)
    sealed, shares = seal_under_guardianship(SECRET, user_half=USER_HALF, policy=policy,
                                             storage=ts.StorageLocation.GUARDIANS)
    assert reconstruct_under_guardianship(
        sealed, user_half=USER_HALF, policy=policy,
        presented_shares=[shares[0], shares[1], shares[3]]) == SECRET


# ------------------------------------------------- revoke-a-share = rotate to a new guardian set
def test_rotate_revokes_old_shares_and_preserves_the_secret():
    old = GuardianshipPolicy(guardians=_mixed_set(), m=3)  # home, laptop, spouse, op-eu, op-us
    sealed, shares = seal_under_guardianship(SECRET, user_half=USER_HALF, policy=old,
                                             storage=ts.StorageLocation.GUARDIANS, context=b"v1")
    # revoke "op-us": the new set drops it
    new = GuardianshipPolicy(guardians=tuple(g for g in _mixed_set() if g.label != "op-us"), m=3)
    new_sealed, new_shares = rotate_guardianship(
        sealed, user_half=USER_HALF, presented_shares=[shares[0], shares[1], shares[3]],
        old_policy=old, new_policy=new, storage=ts.StorageLocation.GUARDIANS, context=b"v2")
    # NEW shares open the NEW sketch and recover the SAME secret
    assert reconstruct_under_guardianship(
        new_sealed, user_half=USER_HALF, policy=new,
        presented_shares=[new_shares[0], new_shares[1], new_shares[3]]) == SECRET
    # OLD shares are useless against the NEW sketch — revocation is real (fresh Shamir split)
    with pytest.raises(ts.UnsealFailed):
        reconstruct_under_guardianship(new_sealed, user_half=USER_HALF, policy=new,
                                       presented_shares=[shares[0], shares[1], shares[3]])
