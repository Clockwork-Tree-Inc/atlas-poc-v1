"""Forward-secure ratcheted signer — correctness + the load-bearing forward-security property.

The whole point (and the A13 structural fix): after ratcheting forward, a signer that is FULLY
compromised (attacker holds its current secret state) STILL cannot produce a valid signature for a
PAST epoch. Backdating is impossible by construction, with no epoch-field check.
"""

import pytest

from atlas.authority.fs_sign import (
    FSError, FSSignature, fs_keygen, fs_verify, _leaf_seed, _auth_path,
)
from atlas.crypto.sign import keypair_from_seed, sign

SEED = bytes(range(32))
MSG = b"grant-body-bytes"


def test_sign_verify_current_epoch():
    pub, s = fs_keygen(SEED, height=3)
    sig = s.sign(MSG)
    assert sig.epoch == 0 and fs_verify(pub, MSG, sig)


def test_epoch_is_intrinsic_and_advances():
    pub, s = fs_keygen(SEED, height=3)
    for expect in range(4):
        sig = s.sign(MSG)
        assert sig.epoch == expect and fs_verify(pub, MSG, sig)
        s.advance()


def test_one_epoch_signs_many_grants():
    pub, s = fs_keygen(SEED, height=3)
    a, b = s.sign(b"grant-A"), s.sign(b"grant-B")     # same epoch, two grants
    assert a.epoch == b.epoch == 0
    assert fs_verify(pub, b"grant-A", a) and fs_verify(pub, b"grant-B", b)


def test_public_key_is_deterministic():
    pub1, _ = fs_keygen(SEED, height=4)
    pub2, _ = fs_keygen(SEED, height=4)
    assert pub1.root == pub2.root and pub1.height == 4


# --------------------------------------------------------------------------- forward security (A13)
def test_forward_security_compromised_state_cannot_backdate():
    pub, s = fs_keygen(SEED, height=3)
    assert fs_verify(pub, MSG, s.sign(MSG))                 # honest epoch-0 signature

    # advance to epoch 3 — this is the COMPROMISE point: the attacker now holds s._state (= state_3).
    for _ in range(3):
        s.advance()
    assert s.epoch == 3

    # Best forgery the compromised state allows: it can only derive the CURRENT leaf key (epoch 3),
    # but it tries to pass it off as an epoch-0 signature (with leaf-0's public auth path).
    leaf_now = keypair_from_seed(_leaf_seed(s._state))       # the only leaf secret they have
    forged = FSSignature(epoch=0, leaf_public=leaf_now.public.encode(),
                         sig=sign(leaf_now, MSG), auth_path=_auth_path(s._levels, 0))
    assert not fs_verify(pub, MSG, forged)                  # REJECTED — leaf/auth-path/root mismatch

    # And they cannot recover the genuine epoch-0 leaf: state_0 is not derivable from state_3 (H is
    # one-way). Confirm the current leaf seed is not the epoch-0 leaf seed.
    _, fresh = fs_keygen(SEED, height=3)
    epoch0_leaf_seed = _leaf_seed(fresh._state)
    assert _leaf_seed(s._state) != epoch0_leaf_seed


def test_forged_and_tampered_signatures_rejected():
    pub, s = fs_keygen(SEED, height=3)
    sig = s.sign(MSG)
    assert not fs_verify(pub, b"different message", sig)              # wrong message
    bad = FSSignature(epoch=1, leaf_public=sig.leaf_public, sig=sig.sig, auth_path=sig.auth_path)
    assert not fs_verify(pub, MSG, bad)                              # wrong epoch claim -> root mismatch
    tampered = FSSignature(epoch=0, leaf_public=sig.leaf_public, sig=b"\x00" * len(sig.sig),
                           auth_path=sig.auth_path)
    assert not fs_verify(pub, MSG, tampered)                         # tampered leaf signature


def test_exhaustion_raises():
    pub, s = fs_keygen(SEED, height=2)      # only 4 epochs
    for _ in range(4):
        s.sign(MSG)
        s.advance()
    with pytest.raises(FSError):
        s.advance()
    with pytest.raises(FSError):
        s.sign(MSG)
