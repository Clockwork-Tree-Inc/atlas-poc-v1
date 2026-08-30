"""Ledger-anchored re-root — compromise recovery (the FUTURE half of A13).

A re-root is authorized by an INDEPENDENT recovery key (not the compromised signing key) and
anchored (unforgeable cutover). After it, the old root is retired: old-root grants no longer verify.
"""

import pytest

from atlas.authority import (
    AuthorityError, ReRoot, RightSet, current_root, fs_keygen, issue_fs, make_reroot, verify_chain,
)
from atlas.crypto.sign import keypair_from_seed, sign

RES = b"space-1"
RECOVERY = keypair_from_seed(b"\x01" * 32)   # the independent recovery authority
THIEF = keypair_from_seed(b"\x09" * 32)       # holds a compromised signing key, NOT the recovery key
A = keypair_from_seed(b"\x02" * 32)


def test_no_reroot_is_genesis():
    gpub, _ = fs_keygen(b"g" * 32, height=3)
    assert current_root(RES, recovery_public=RECOVERY.public, genesis_root=gpub, reroots=[]) == gpub


def test_valid_reroot_moves_the_root():
    gpub, _ = fs_keygen(b"g" * 32, height=3)
    npub, _ = fs_keygen(b"n" * 32, height=3)
    rr = make_reroot(RECOVERY, resource=RES, new_root=npub, effective_epoch=5)
    assert current_root(RES, recovery_public=RECOVERY.public, genesis_root=gpub, reroots=[rr]) == npub


def test_thief_cannot_reroot():
    gpub, _ = fs_keygen(b"g" * 32, height=3)
    evil, _ = fs_keygen(b"evil" * 8, height=3)
    forged = ReRoot(resource=RES, new_root=evil, effective_epoch=9)
    forged.sig = sign(THIEF, forged._body())      # signed by the thief, not the recovery authority
    # ignored -> the root does NOT move (a compromised signing key can't re-root to itself)
    assert current_root(RES, recovery_public=RECOVERY.public, genesis_root=gpub, reroots=[forged]) == gpub


def test_latest_reroot_wins():
    gpub, _ = fs_keygen(b"g" * 32, height=3)
    n1, _ = fs_keygen(b"n1" * 16, height=3)
    n2, _ = fs_keygen(b"n2" * 16, height=3)
    r1 = make_reroot(RECOVERY, resource=RES, new_root=n1, effective_epoch=5)
    r2 = make_reroot(RECOVERY, resource=RES, new_root=n2, effective_epoch=10)
    assert current_root(RES, recovery_public=RECOVERY.public, genesis_root=gpub,
                        reroots=[r2, r1]) == n2      # latest effective epoch wins, order-independent


def test_compromise_recovery_end_to_end():
    # genesis root issues a legit grant
    gpub, gsigner = fs_keygen(b"g" * 32, height=3)
    old_grant = issue_fs(gsigner, grantee=A.public, resource=RES, rights=RightSet(3))
    assert verify_chain([old_grant], resource=RES, resource_root=gpub, now=1000) == RightSet(3)

    # compromise detected -> recovery authority re-roots to a fresh, unrelated root
    npub, nsigner = fs_keygen(b"n" * 32, height=3)
    rr = make_reroot(RECOVERY, resource=RES, new_root=npub, effective_epoch=1)
    cur = current_root(RES, recovery_public=RECOVERY.public, genesis_root=gpub, reroots=[rr])
    assert cur == npub

    # the old root is RETIRED: its grants no longer verify — even the compromised old signer can issue
    # nothing that passes, because verification runs against the CURRENT (new) root.
    with pytest.raises(AuthorityError):
        verify_chain([old_grant], resource=RES, resource_root=cur, now=1000)
    forged_by_thief = issue_fs(gsigner, grantee=A.public, resource=RES, rights=RightSet(5))
    with pytest.raises(AuthorityError):
        verify_chain([forged_by_thief], resource=RES, resource_root=cur, now=1000)

    # live authority continues under the new root
    new_grant = issue_fs(nsigner, grantee=A.public, resource=RES, rights=RightSet(3))
    assert verify_chain([new_grant], resource=RES, resource_root=cur, now=1000) == RightSet(3)
