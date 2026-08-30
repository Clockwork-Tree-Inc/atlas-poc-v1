"""TSK t-of-n threshold: configurable m-of-n over a holder set, default 2-of-3,
with the anti-remote-recovery invariant (no all-institutional quorum). The pinned
KAT (fixed shares -> seed via the deterministic combine) is the byte-parity contract
with Swift `TSKThresholdTests`."""

import itertools

import pytest

from atlas.crypto import shamir
from atlas.keys.tsk_threshold import (
    DEFAULT_HOLDERS,
    DEFAULT_POLICY,
    AllInstitutionalQuorum,
    HolderCountMismatch,
    TSKShare,
    reconstruct_tsk,
    split_tsk,
)
from atlas.recovery.threshold_seal import Custodian, ThresholdPolicy


def test_default_is_2_of_3_any_two_reconstruct():
    seed = bytes(range(32))
    shares = split_tsk(seed)
    assert len(shares) == 3
    for combo in itertools.combinations(shares, 2):
        assert reconstruct_tsk(list(combo)) == seed


def test_general_m_of_n_as_many_as_you_want():
    # 3-of-5 over five holders (four personal + one institutional).
    seed = bytes(range(40))
    holders = [
        Custodian("wallet-se", institutional=False),
        Custodian("usb", institutional=False),
        Custodian("recovery-card", institutional=False),
        Custodian("guardian-alice", institutional=False),
        Custodian("server-hsm", institutional=True),
    ]
    policy = ThresholdPolicy(n=5, m=3)
    shares = split_tsk(seed, policy=policy, holders=holders)
    assert len(shares) == 5
    for combo in itertools.combinations(shares, 3):
        assert reconstruct_tsk(list(combo)) == seed
    # two shares (below threshold) must NOT reconstruct
    assert reconstruct_tsk(shares[:2]) != seed


def test_anti_remote_recovery_rejects_all_institutional_quorum_at_split():
    # 2-of-3 with TWO institutional holders: a {hsm-a, hsm-b} quorum would be all-remote.
    holders = [
        Custodian("hsm-a", institutional=True),
        Custodian("hsm-b", institutional=True),
        Custodian("wallet-se", institutional=False),
    ]
    with pytest.raises(AllInstitutionalQuorum):
        split_tsk(bytes(range(32)), policy=ThresholdPolicy(n=3, m=2), holders=holders)


def test_anti_remote_recovery_rejects_all_institutional_quorum_at_reconstruct():
    # Even if shares are assembled by hand, an all-institutional presented quorum is refused.
    seed = bytes(range(32))
    raw = shamir.split(seed, n=3, k=2)
    inst_shares = [
        TSKShare(Custodian("hsm-a", institutional=True), raw[0]),
        TSKShare(Custodian("hsm-b", institutional=True), raw[1]),
    ]
    with pytest.raises(AllInstitutionalQuorum):
        reconstruct_tsk(inst_shares)


def test_holder_count_must_match_policy():
    with pytest.raises(HolderCountMismatch):
        split_tsk(bytes(range(32)), policy=ThresholdPolicy(n=3, m=2),
                  holders=DEFAULT_HOLDERS[:2])


# --- parity KAT: fixed shares -> seed via deterministic combine (locks Swift) ---
_KAT_SEED = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
_KAT_SHARES = {
    1: "2e72bea056b5ef6b9bb7bcd066bfd53516b9701fc66476b7bbd709caf316a71b",
    2: "5cd7010e608e6f4faec5866d831998702c5a866b5b3746ecee05f759b2507c2c",
    3: "72b49d9d726ee653bdeb9006297ba3ba3af2d447d906562cdd4b54288d9b35c8",
}


def _share(idx: int, institutional: bool = False) -> TSKShare:
    return TSKShare(Custodian(f"h{idx}", institutional=institutional),
                    shamir.Share(index=idx, y=bytes.fromhex(_KAT_SHARES[idx])))


def test_parity_kat_any_two_of_three_combine_to_seed():
    seed = bytes.fromhex(_KAT_SEED)
    for a, b in itertools.combinations([1, 2, 3], 2):
        assert reconstruct_tsk([_share(a), _share(b)]) == seed
