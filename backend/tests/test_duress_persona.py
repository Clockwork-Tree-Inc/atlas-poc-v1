"""#40 — duress → cryptographically-scoped persona. The decoy presented under coercion is a full,
plausible persona that is UNLINKABLE to the root System-ID and to every real persona, and can never
collide with a real profile()."""
import os

from atlas.keys.identity import PseudonymTier, build_identity_tree


def test_duress_persona_is_deterministic_per_user():
    seed = os.urandom(32)
    a = build_identity_tree(seed).duress_persona(0)
    b = build_identity_tree(seed).duress_persona(0)          # same user, later session
    assert a.handle == b.handle                              # stable decoy across sessions


def test_duress_persona_unlinkable_to_root_and_real_personas():
    tree = build_identity_tree(os.urandom(32))
    d = tree.duress_persona(0)
    # not the root / System-ID
    assert d.handle != tree.root_handle
    assert d.handle != tree.system_id_handle()
    # not any real persona, at any tier
    for uname in ("aun", "horseshit", "journalist"):
        for tier in (PseudonymTier.PUBLIC, PseudonymTier.ANONYMOUS):
            assert d.handle != tree.profile(uname, tier).handle


def test_duress_domain_cannot_collide_with_a_real_profile_of_the_same_name():
    """A real user who happens to name a persona 'duress:0' still gets a DIFFERENT handle — the
    decoy lives in its own HKDF domain, so it can never be impersonated or collided into."""
    tree = build_identity_tree(os.urandom(32))
    assert tree.duress_persona(0).handle != tree.profile("duress:0", PseudonymTier.ANONYMOUS).handle
    assert tree.duress_persona(0).handle != tree.profile("duress:0", PseudonymTier.PUBLIC).handle


def test_distinct_slots_are_distinct_and_unlinkable():
    tree = build_identity_tree(os.urandom(32))
    assert tree.duress_persona(0).handle != tree.duress_persona(1).handle


def test_duress_persona_features_are_unlinkable_too():
    """Its messaging/vault slices don't cross-link to a real persona's — the relay/forum can't tie
    the decoy's mailbox to the real you."""
    tree = build_identity_tree(os.urandom(32))
    d = tree.duress_persona(0)
    real = tree.profile("aun", PseudonymTier.PUBLIC)
    assert d.feature("messaging").handle != real.feature("messaging").handle
    assert d.feature("vault").handle != real.feature("vault").handle


def test_duress_personas_of_different_users_do_not_collide():
    a = build_identity_tree(os.urandom(32)).duress_persona(0)
    b = build_identity_tree(os.urandom(32)).duress_persona(0)
    assert a.handle != b.handle
