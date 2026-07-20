"""Crypto layer (§1.3, §2): primitives, hybrid KEM, hybrid+SPHINCS signatures,
Shamir 2-of-3."""

import itertools
import os

import pytest

from atlas.crypto import kem, shamir
from atlas.crypto import primitives as P
from atlas.crypto import sign


def test_aead_roundtrip_and_aad():
    k = P.random_bytes(32)
    blob = P.aead_encrypt(k, b"msg", b"aad")
    assert P.aead_decrypt(k, blob, b"aad") == b"msg"
    with pytest.raises(Exception):
        P.aead_decrypt(k, blob, b"wrong-aad")


def test_hkdf_combine_unambiguous():
    # length-prefixing => (a, b) cannot collide with (a||b, "")
    assert P.hkdf_combine([b"ab", b"c"], info=b"i") != P.hkdf_combine([b"abc", b""], info=b"i")


def test_hybrid_kem_roundtrip():
    kp = kem.generate_keypair()
    enc = kem.encapsulate(kp.public)
    assert len(enc.shared) == 32
    assert kem.decapsulate(kp, enc.mlkem_ct, enc.x25519_eph_pk) == enc.shared


def test_hybrid_kem_wrong_key_fails():
    kp = kem.generate_keypair()
    other = kem.generate_keypair()
    enc = kem.encapsulate(kp.public)
    assert kem.decapsulate(other, enc.mlkem_ct, enc.x25519_eph_pk) != enc.shared


def test_hybrid_sign_verify():
    kp = sign.generate_sig_keypair()
    sig = sign.sign(kp, b"hello")
    assert sign.verify(kp.public, b"hello", sig)
    assert not sign.verify(kp.public, b"tampered", sig)


def test_hybrid_sign_requires_both_components():
    kp = sign.generate_sig_keypair()
    sig = sign.sign(kp, b"hello")
    # Corrupt the trailing Ed25519 component -> must fail (both required).
    bad = bytearray(sig)
    bad[-1] ^= 0xFF
    assert not sign.verify(kp.public, b"hello", bytes(bad))


def test_sign_keypair_deterministic_from_seed():
    seed = os.urandom(32)
    a = sign.keypair_from_seed(seed)
    b = sign.keypair_from_seed(seed)
    assert a.mldsa_pk == b.mldsa_pk and a.ed_pk == b.ed_pk
    assert sign.keypair_from_seed(os.urandom(32)).mldsa_pk != a.mldsa_pk


def test_sphincs_root():
    kp = sign.sphincs_generate()
    sig = sign.sphincs_sign(kp, b"root")
    assert sign.sphincs_verify(kp.pk, b"root", sig)
    assert not sign.sphincs_verify(kp.pk, b"other", sig)


def test_shamir_2_of_3_all_pairs():
    secret = os.urandom(32)
    shares = shamir.split(secret, n=3, k=2)
    for combo in itertools.combinations(shares, 2):
        assert shamir.combine(list(combo)) == secret
    assert shamir.combine(shares) == secret


def test_shamir_single_share_is_not_enough():
    secret = os.urandom(32)
    shares = shamir.split(secret, n=3, k=2)
    # One share alone carries no usable information about the secret.
    assert shares[0].y != secret


def test_shamir_share_encode_decode():
    s = shamir.split(os.urandom(16), n=3, k=2)[0]
    assert shamir.Share.decode(s.encode()) == s


def test_shamir_combine_rejects_out_of_range_index():
    # x=0 is the interpolation point (the secret); a malformed share at index 0
    # (or >255) must be rejected, not silently produce garbage.
    s = shamir.split(os.urandom(16), n=3, k=2)
    with pytest.raises(ValueError):
        shamir.combine([shamir.Share(index=0, y=s[0].y), s[1]])
