"""did:cid exposer — self-certifying, content-addressed DIDs over Atlas keys."""
from atlas.crypto.sign import keypair_from_seed
from atlas.did_cid import did_cid, did_for, verify_did


def kp(n):
    return keypair_from_seed(bytes([n]) * 32)


def test_did_format_and_determinism():
    d = did_for(kp(1).public)
    assert d.startswith("did:cid:f")
    assert d == did_for(kp(1).public)                 # deterministic: same key -> same DID


def test_different_keys_different_dids():
    assert did_for(kp(1).public) != did_for(kp(2).public)


def test_multi_key_did_is_order_independent():
    a, b = kp(1).public, kp(2).public
    assert did_cid([a, b]) == did_cid([b, a])         # sorted canonicalization


def test_self_certifying_verify():
    keys = [kp(1).public]
    d = did_for(kp(1).public)
    assert verify_did(d, keys)                         # the DID proves its own binding to the key
    assert not verify_did(d, [kp(2).public])           # a different key does not match the DID


def test_single_key_matches_list_form():
    assert did_for(kp(3).public) == did_cid([kp(3).public])
