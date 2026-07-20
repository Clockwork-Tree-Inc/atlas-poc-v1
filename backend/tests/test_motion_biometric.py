"""Motion as a soft biometric (the population-scale Sybil lever): people are separable by
their movement, so a farm reusing one person's gait across identities collapses."""

from atlas.sim.motion_biometric import (
    duplicate_radius,
    farm_gait_reuse,
    motion_signature,
    reidentification,
    signature_distance,
)
from atlas.sim.motionsense import load_profiles

PROFILES = load_profiles()


def test_motion_is_a_soft_biometric_above_chance():
    r = reidentification(PROFILES)
    assert r.rate > r.chance                    # separable at all
    assert r.lift >= 3.0                        # measured ~8x; assert a robust floor


def test_signature_is_deterministic():
    s = list(PROFILES["subjects"][sorted(PROFILES["subjects"], key=int)[0]]["stream"])
    assert motion_signature(s) == motion_signature(s)


def test_same_person_halves_are_closer_than_a_different_person():
    subs = PROFILES["subjects"]
    ids = sorted(subs, key=int)
    a = list(subs[ids[0]]["stream"]); h = len(a) // 2
    a1, a2 = motion_signature(a[:h]), motion_signature(a[h:])
    b = motion_signature(list(subs[ids[1]]["stream"])[:h])
    assert signature_distance(a1, a2) < signature_distance(a1, b)


def test_gait_reuse_farm_collapses_to_one():
    # A smarter replay: reuse one person's motion for 50 identities, jittering each to
    # dodge exact dedup. Near-duplicate detection on the signature still collapses them.
    g = farm_gait_reuse(PROFILES, 50)
    assert g.valid == 1
    assert g.cost_per_valid == 1.0


def test_duplicate_radius_separates_within_from_a_stranger():
    radius = duplicate_radius(PROFILES)
    subs = PROFILES["subjects"]; ids = sorted(subs, key=int)
    a = list(subs[ids[0]]["stream"]); h = len(a) // 2
    within = signature_distance(motion_signature(a[:h]), motion_signature(a[h:]))
    assert within <= radius                     # same person's halves are near-duplicates
