"""Tests for the recovery-tier selection (TRUST_LAYER.md #6).

Asserts the ladder picks the strongest reachable tier, the delegation map is complete, and
the load-bearing product guarantee: with (name+password) + a recovery person you are NEVER
permanently locked out — the physical-self floor is always reachable, no device, no guardians.
"""

import pytest

from atlas.recovery.tiers import (
    AvailableFactors,
    NoTierReachable,
    RecoveryTier,
    TIER_OWNER,
    never_locked_out,
    reachable_tiers,
    select_tier,
)


def test_device_present_is_strongest_when_you_hold_a_half():
    f = AvailableFactors(user_half=True, guardian_quorum=True, name_password=True,
                         recovery_person=True)
    assert select_tier(f) is RecoveryTier.DEVICE_PRESENT
    # every tier is reachable here; the ladder returns them strongest-first
    assert reachable_tiers(f) == [RecoveryTier.DEVICE_PRESENT, RecoveryTier.SOCIAL,
                                  RecoveryTier.PHYSICAL_SELF]


def test_social_selected_when_device_lost_but_guardians_reachable():
    f = AvailableFactors(user_half=False, guardian_quorum=True, name_password=True,
                         recovery_person=False)
    assert select_tier(f) is RecoveryTier.SOCIAL


def test_social_needs_the_ceremony_half_too():
    # a guardian quorum WITHOUT name+password cannot open it (no ceremony half).
    f = AvailableFactors(guardian_quorum=True, name_password=False)
    assert RecoveryTier.SOCIAL not in reachable_tiers(f)


def test_physical_self_is_the_floor():
    # no device, no guardians — just you: name+password + a live recovery person.
    f = AvailableFactors(name_password=True, recovery_person=True)
    assert select_tier(f) is RecoveryTier.PHYSICAL_SELF
    assert never_locked_out(f) is True


def test_never_locked_out_holds_with_only_self():
    assert never_locked_out(AvailableFactors(name_password=True, recovery_person=True))


def test_locked_out_without_password_or_person():
    # forgetting the password OR being unable to reach a recovery person is the only lockout.
    assert not never_locked_out(AvailableFactors(name_password=True, recovery_person=False))
    assert not never_locked_out(AvailableFactors(name_password=False, recovery_person=True))
    with pytest.raises(NoTierReachable):
        select_tier(AvailableFactors(name_password=False, recovery_person=True))


def test_device_present_ignores_missing_ceremony_half():
    # holding your own half is self-sufficient — no name+password or third party needed.
    f = AvailableFactors(user_half=True)
    assert select_tier(f) is RecoveryTier.DEVICE_PRESENT
    assert never_locked_out(f) is False   # ...but that alone isn't the *floor* guarantee


def test_tier_owner_map_is_complete():
    # every tier delegates to a concrete owning module.
    assert set(TIER_OWNER) == set(RecoveryTier)
    assert TIER_OWNER[RecoveryTier.PHYSICAL_SELF] == "realid.recovery_anchor"
    assert TIER_OWNER[RecoveryTier.SOCIAL] == "recovery.guardianship"
    assert TIER_OWNER[RecoveryTier.DEVICE_PRESENT] == "recovery.threshold_seal"


def test_tiers_are_ordered_by_assurance():
    assert RecoveryTier.DEVICE_PRESENT > RecoveryTier.SOCIAL > RecoveryTier.PHYSICAL_SELF
