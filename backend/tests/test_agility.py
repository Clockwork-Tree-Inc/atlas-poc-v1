"""Tests for the crypto-agility seam (TRUST_LAYER.md #10)."""

import pytest

from atlas.crypto.agility import (
    AgilityError,
    CryptoSuite,
    NoCommonSuite,
    SchemeFamily,
    SchemeId,
    SchemeRegistry,
    UnknownScheme,
    negotiate,
)

F = SchemeFamily


def _registry() -> SchemeRegistry:
    r = SchemeRegistry()
    # the schemes Atlas actually ships, registered by id (pq flag = machine-readable posture)
    r.register(SchemeId(F.KEM, "ml-kem-768+x25519", pq=True), object(), default=True)
    r.register(SchemeId(F.SIGNATURE, "ml-dsa-65+ed25519", pq=True), object(), default=True)
    r.register(SchemeId(F.SIGNATURE, "sphincs+", pq=True), object())
    r.register(SchemeId(F.CREDENTIAL, "bbs+", pq=False), object(), default=True)  # classical anon
    r.register(SchemeId(F.CREDENTIAL, "ps", pq=False), object())                  # perf swap
    return r


def test_registry_get_default_available_and_unknown():
    r = _registry()
    assert r.default(F.KEM) == "ml-kem-768+x25519"
    assert r.get(F.CREDENTIAL, "ps") is not None
    names = {s.name for s in r.available(F.CREDENTIAL)}
    assert names == {"bbs+", "ps"}
    with pytest.raises(UnknownScheme):
        r.get(F.CREDENTIAL, "nope")


def test_swap_needs_no_call_site_change():
    # the registry lets the credential scheme swap from bbs+ to ps by NAME, same call site.
    r = _registry()
    a = r.get(F.CREDENTIAL, r.default(F.CREDENTIAL))
    r.register(SchemeId(F.CREDENTIAL, "ps", pq=False), object(), default=True)  # promote ps
    b = r.get(F.CREDENTIAL, r.default(F.CREDENTIAL))
    assert r.default(F.CREDENTIAL) == "ps" and a is not b


def test_suite_id_deterministic_and_sensitive():
    s = CryptoSuite(version=1, kem="ml-kem-768+x25519", signature="ml-dsa-65+ed25519", credential="bbs+")
    assert s.suite_id() == CryptoSuite(1, "ml-kem-768+x25519", "ml-dsa-65+ed25519", "bbs+").suite_id()
    # any field change -> different id
    assert s.suite_id() != CryptoSuite(2, "ml-kem-768+x25519", "ml-dsa-65+ed25519", "bbs+").suite_id()
    assert s.suite_id() != CryptoSuite(1, "ml-kem-768+x25519", "sphincs+", "bbs+").suite_id()
    assert s.suite_id() != CryptoSuite(1, "ml-kem-768+x25519", "ml-dsa-65+ed25519", "ps").suite_id()


def test_suite_id_framing_is_unambiguous():
    # length-prefix framing: a boundary shift must not collide.
    a = CryptoSuite(1, "ab", "c", "d").suite_id()
    b = CryptoSuite(1, "a", "bc", "d").suite_id()
    assert a != b


def test_is_post_quantum():
    r = _registry()
    pq_sig = CryptoSuite(1, "ml-kem-768+x25519", "sphincs+", "bbs+")
    # bbs+ is classical -> the whole suite is not fully PQ (unlinkability is classical)
    assert not pq_sig.is_post_quantum(r)
    # if every family were PQ it would be True (register a PQ credential to show it)
    r.register(SchemeId(F.CREDENTIAL, "pq-anoncred", pq=True), object())
    assert CryptoSuite(1, "ml-kem-768+x25519", "sphincs+", "pq-anoncred").is_post_quantum(r)


def test_negotiate_picks_top_common_in_preference_order():
    strong = CryptoSuite(2, "ml-kem-768+x25519", "ml-dsa-65+ed25519", "ps")
    weak = CryptoSuite(1, "ml-kem-768+x25519", "ml-dsa-65+ed25519", "bbs+")
    preference = [strong, weak]                      # best first
    # remote supports only the weaker one -> negotiate falls to it
    assert negotiate(preference, {weak.suite_id()}) == weak
    # remote supports both -> the top preference wins
    assert negotiate(preference, {strong.suite_id(), weak.suite_id()}) == strong


def test_negotiate_fail_closed_on_no_overlap():
    a = CryptoSuite(1, "ml-kem-768+x25519", "ml-dsa-65+ed25519", "bbs+")
    with pytest.raises(NoCommonSuite):
        negotiate([a], {b"some-other-suite-id"})


def test_negotiate_respects_a_strength_floor():
    r = _registry()
    r.register(SchemeId(F.CREDENTIAL, "pq-anoncred", pq=True), object())
    strong = CryptoSuite(1, "ml-kem-768+x25519", "sphincs+", "pq-anoncred")   # fully PQ
    classical = CryptoSuite(1, "ml-kem-768+x25519", "ml-dsa-65+ed25519", "bbs+")  # bbs+ classical
    pq_floor = lambda s: s.is_post_quantum(r)                                  # noqa: E731
    # a MITM strips the overlap to only the classical suite -> fail closed under a PQ floor.
    with pytest.raises(NoCommonSuite):
        negotiate([classical], {classical.suite_id()}, acceptable=pq_floor)
    # when a PQ suite is mutually supported, it is chosen.
    assert negotiate([strong, classical], {strong.suite_id(), classical.suite_id()},
                     acceptable=pq_floor) == strong


def test_no_default_raises():
    r = SchemeRegistry()
    with pytest.raises(AgilityError):
        r.default(F.KEM)
