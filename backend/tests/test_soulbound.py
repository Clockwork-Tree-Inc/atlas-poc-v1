"""Soul-bound tokens — non-transferable, identity-bound, non-monetary participation credentials."""

from atlas.crypto.sign import keypair_from_seed
from atlas.participation import (
    PARTICIPATION, SoulboundCollection, collect_participation, issue_sbt, verify_sbt,
)


def kp(n):
    return keypair_from_seed(bytes([n]) * 32)


A, B, ORG = kp(1), kp(2), kp(9)


# --------------------------------------------------------------------------- collect + accumulate
def test_collect_participation_and_balance():
    col = SoulboundCollection(A.public)
    for e in (1, 2, 3):
        assert col.add(collect_participation(A, epoch=e, pole_commitment=b"pole-" + bytes([e])))
    assert col.balance(PARTICIPATION) == 3
    assert col.epochs() == [1, 2, 3]


def test_one_per_epoch_no_inflation():
    col = SoulboundCollection(A.public)
    col.add(collect_participation(A, epoch=5, pole_commitment=b"x"))
    col.add(collect_participation(A, epoch=5, pole_commitment=b"y"))   # same epoch, different payload
    assert col.balance(PARTICIPATION) == 1                             # one presence per epoch


def test_self_issued_participation_verifies():
    t = collect_participation(A, epoch=1)
    assert t.issuer.encode() == A.public.encode()                     # issuer == holder
    assert t.holder.encode() == A.public.encode()
    assert verify_sbt(t) is True


# --------------------------------------------------------------------------- non-transferability
def test_cannot_collect_a_token_bound_to_someone_else():
    a_token = collect_participation(A, epoch=1)                        # bound to A's soul
    b_col = SoulboundCollection(B.public)
    assert b_col.add(a_token) is False                                # B cannot hold A's soul-bound token
    assert b_col.balance() == 0


def test_no_transfer_by_rebinding():
    # "Transferring" A's token to B = changing the holder, which breaks the issuer signature.
    a_token = collect_participation(A, epoch=1)
    a_token.holder = B.public                                         # attempt to re-home it
    assert verify_sbt(a_token) is False                              # signature no longer valids
    assert SoulboundCollection(B.public).add(a_token) is False


def test_tampered_token_rejected():
    t = collect_participation(A, epoch=1)
    t.epoch = 999                                                    # tamper after signing
    assert verify_sbt(t) is False


# --------------------------------------------------------------------------- issued badges (org -> holder)
def test_org_issued_badge_collectible_by_its_holder():
    badge = issue_sbt(ORG, holder=A.public, kind=b"atlas/badge/pilot-2026", epoch=1)
    assert verify_sbt(badge) is True
    col = SoulboundCollection(A.public)
    assert col.add(badge) is True                                    # A holds the badge ORG bound to A
    assert col.balance(b"atlas/badge/pilot-2026") == 1
    assert col.balance(PARTICIPATION) == 0                           # kinds are counted separately


def test_org_badge_bound_to_A_not_collectible_by_B():
    badge = issue_sbt(ORG, holder=A.public, kind=b"atlas/badge/pilot-2026", epoch=1)
    assert SoulboundCollection(B.public).add(badge) is False         # bound to A, not transferable to B
