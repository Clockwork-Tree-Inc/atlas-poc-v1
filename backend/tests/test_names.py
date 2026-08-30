"""Human-readable naming/discovery registry: claim/resolve/uniqueness, control-your-own-handle,
release + revoke."""

import os

import pytest

from atlas.crypto.sign import sign
from atlas.keys.identity import PseudonymTier, build_identity_tree
from atlas.names import NameClaim, NameRegistry, _claim_body, claim_name, verify_claim


def _identity(name="p"):
    return build_identity_tree(os.urandom(32)).profile(name, PseudonymTier.PUBLIC).identity


def test_claim_resolve_and_uniqueness():
    shop = _identity("shop")
    reg = NameRegistry()
    c = claim_name(shop, "coolshop")
    assert verify_claim(c)
    reg.register(c)
    assert reg.resolve("coolshop") == shop.handle
    # a DIFFERENT persona cannot take a held name
    with pytest.raises(ValueError):
        reg.register(claim_name(_identity("other"), "coolshop"))
    # the SAME handle may refresh its own claim (new epoch)
    reg.register(claim_name(shop, "coolshop", epoch=1))
    assert reg.resolve("coolshop") == shop.handle
    assert reg.resolve("unclaimed") is None


def test_cannot_name_a_handle_you_dont_control():
    victim = _identity("victim")
    attacker = _identity("atk")
    # forge: point the name at the victim's handle but sign with the attacker's key
    forged = NameClaim(name="victimname", handle=victim.handle, public=attacker.public, epoch=0)
    forged.sig = sign(attacker.keypair, _claim_body("victimname", victim.handle, 0))
    assert not verify_claim(forged)              # handle != handle_of(attacker.public)
    with pytest.raises(ValueError):
        NameRegistry().register(forged)


def test_release_and_revoke():
    p = _identity("p")
    reg = NameRegistry()
    reg.register(claim_name(p, "freed"))
    reg.release(p, "freed")
    assert reg.resolve("freed") is None
    # after release, someone else CAN take it
    q = _identity("q")
    reg.register(claim_name(q, "freed"))
    assert reg.resolve("freed") == q.handle
    # revoke frees AND blocks re-registration
    reg.revoke("freed")
    assert reg.resolve("freed") is None
    with pytest.raises(ValueError):
        reg.register(claim_name(q, "freed"))
