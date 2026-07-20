"""Personas — multi-persona identity on one blind System-ID.

Asserts the core properties the design promises:
  * a persona is DETERMINISTIC (your card reopens the same persona anywhere, nothing stored);
  * personas are mutually UNLINKABLE and unlinkable to the real you / root / System-ID handle;
  * each persona owns its own per-feature slices (messaging / vault / forum), themselves unlinkable;
  * the blind login SELECTOR is independent of the System-ID (the server learns nothing about
    which real person, or which other personas, a login belongs to).
"""

import os

import pytest

from atlas.keys.identity import build_identity_tree, PseudonymTier
from atlas.persona import Persona, open_persona, persona_selector

SEED = bytes(range(32))
PW = "correct horse battery staple"


def _tree(seed=SEED):
    return build_identity_tree(seed)


# --------------------------------------------------------------------------- determinism
def test_persona_is_deterministic_across_rebuilds():
    a = open_persona(_tree(), "horseshit", PW)
    b = open_persona(_tree(), "horseshit", PW)          # rebuilt tree, same inputs
    assert a.handle == b.handle                          # same crypto identity
    assert a.selector == b.selector                      # same blind login handle
    assert a.feature_handle("messaging") == b.feature_handle("messaging")


# --------------------------------------------------------------------------- cross-persona unlinkability
def test_two_personas_are_mutually_unlinkable():
    tree = _tree()
    real = open_persona(tree, "aunali", PW, tier=PseudonymTier.PUBLIC)
    alt = open_persona(tree, "horseshit", PW, tier=PseudonymTier.ANONYMOUS)
    # distinct personas of the SAME person share no observable token.
    assert real.handle != alt.handle
    assert real.selector != alt.selector
    # neither persona's handle is the root / System-ID handle (the cross-partition master ids).
    for p in (real, alt):
        assert p.handle != tree.root_handle
        assert p.handle != tree.system_id_handle()


def test_same_username_different_tier_is_a_different_persona():
    tree = _tree()
    pub = open_persona(tree, "aunali", PW, tier=PseudonymTier.PUBLIC)
    anon = open_persona(tree, "aunali", PW, tier=PseudonymTier.ANONYMOUS)
    assert pub.handle != anon.handle                     # tier partitions the persona


# --------------------------------------------------------------------------- per-feature slices
def test_persona_feature_slices_are_distinct_and_unlinkable():
    p = open_persona(_tree(), "horseshit", PW)
    msg = p.feature_handle("messaging")
    vault = p.feature_handle("vault")
    forum = p.feature_handle("forum")
    handles = {msg, vault, forum, p.handle}
    assert len(handles) == 4                              # persona id + 3 slices all distinct


def test_feature_slices_do_not_cross_link_between_personas():
    tree = _tree()
    a = open_persona(tree, "aunali", PW, tier=PseudonymTier.PUBLIC)
    b = open_persona(tree, "horseshit", PW, tier=PseudonymTier.ANONYMOUS)
    # persona A's messaging is not persona B's messaging — no shared token per surface.
    assert a.feature_handle("messaging") != b.feature_handle("messaging")
    assert a.feature_handle("vault") != b.feature_handle("vault")


# --------------------------------------------------------------------------- blind login selector
def test_selector_is_independent_of_the_system_id():
    # The blind login handle is a function of (username, password) ONLY — same across DIFFERENT
    # people (different System-IDs). So the server keying on it learns nothing about which real
    # person, or which other personas, the login belongs to.
    s1 = persona_selector("horseshit", PW)
    s2_other_person = open_persona(_tree(os.urandom(32)), "horseshit", PW).selector
    assert s1 == s2_other_person


def test_selector_changes_with_password_and_username():
    assert persona_selector("horseshit", PW) != persona_selector("horseshit", "other-pw")
    assert persona_selector("horseshit", PW) != persona_selector("someone-else", PW)


def test_different_person_same_login_has_a_different_crypto_identity():
    # Same (username, password) -> same blind SELECTOR (a collision the server disambiguates by
    # which sealed bridge opens), but the crypto IDENTITY is System-ID-bound, so it differs.
    me = open_persona(_tree(), "horseshit", PW)
    them = open_persona(_tree(os.urandom(32)), "horseshit", PW)
    assert me.selector == them.selector                  # blind selector collides (identity-independent)
    assert me.handle != them.handle                      # crypto identity is bound to the System-ID


def test_username_is_case_and_space_folded():
    assert persona_selector("  HorseShit ", PW) == persona_selector("horseshit", PW)
