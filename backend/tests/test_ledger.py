"""Tests for individual ledgers + global anchoring + per-conversation choice (#8/#9).

Properties:
  * Merkle: deterministic root; every-index inclusion proof verifies (incl. odd leaf counts);
    tamper fails.
  * Individual ledger holds only COMMITMENTS (never content); commitments hide + bind.
  * Global anchor: append-only, tamper-evident, drand-round-bound, per-owner root lookup.
  * #9: ACCOUNTABLE commits + anchors (selectively provable later); DENIABLE commits nothing.
  * Selective disclosure: proving one message reveals only that message.
"""

import pytest

from atlas.crypto.primitives import random_bytes
from atlas.ledger import merkle
from atlas.ledger.conversation import (
    AnchoredMessage,
    is_anchored_mode,
    prove_message,
    record_message,
)
from atlas.ledger.global_anchor import GlobalAnchorLog
from atlas.ledger.individual import IndividualLedger, commit
from atlas.session.conversation import ConversationMode


# --------------------------------------------------------------------------- merkle
def test_merkle_root_deterministic_and_leaf_sensitive():
    leaves = [random_bytes(32) for _ in range(5)]
    assert merkle.merkle_root(leaves) == merkle.merkle_root(list(leaves))
    other = list(leaves)
    other[2] = random_bytes(32)
    assert merkle.merkle_root(other) != merkle.merkle_root(leaves)


def test_merkle_empty_and_single():
    assert merkle.merkle_root([]) == merkle.empty_root()
    one = random_bytes(32)
    assert merkle.merkle_root([one]) == merkle.leaf_hash(one)


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 9, 16, 17])
def test_merkle_inclusion_every_index(n):
    leaves = [random_bytes(32) for _ in range(n)]
    root = merkle.merkle_root(leaves)
    for i in range(n):
        proof = merkle.inclusion_proof(leaves, i)
        assert merkle.verify_inclusion(leaves[i], proof, root)
        # a wrong leaf at the same path must fail
        assert not merkle.verify_inclusion(random_bytes(32), proof, root)


def test_merkle_proof_against_wrong_root_fails():
    leaves = [random_bytes(32) for _ in range(6)]
    proof = merkle.inclusion_proof(leaves, 3)
    assert not merkle.verify_inclusion(leaves[3], proof, random_bytes(32))


# --------------------------------------------------------------------------- commitments
def test_commit_hides_and_binds():
    content = b"hello world"
    c1, o1 = commit(content)
    c2, o2 = commit(content)
    assert o1 != o2 and c1 != c2                      # hiding: fresh opening each time
    assert commit(content, o1)[0] == c1               # binding: reproducible with the opening
    assert commit(b"other", o1)[0] != c1              # different content -> different commitment


# --------------------------------------------------------------------------- individual ledger
def test_individual_ledger_append_and_root_changes():
    led = IndividualLedger(owner_id=b"user-A")
    r0 = led.root
    c, _ = commit(b"m0")
    assert led.append(c) == 0
    assert len(led) == 1 and led.contains(c) and led.root != r0


def test_individual_ledger_holds_only_commitments_not_content():
    led = IndividualLedger(owner_id=b"user-A")
    content = b"secret message content"
    c, _ = commit(content)
    led.append(c)
    # the leaf is the commitment, and the content is not recoverable from it
    assert led._leaves == [c]
    assert content not in c


def test_individual_ledger_inclusion_proof():
    led = IndividualLedger(owner_id=b"space-1")
    commits = []
    for i in range(6):
        c, _ = commit(f"m{i}".encode())
        led.append(c)
        commits.append(c)
    for i, c in enumerate(commits):
        proof = led.prove(i)
        assert proof.commitment == c and proof.root == led.root and proof.verify()


# --------------------------------------------------------------------------- global anchor
def test_global_anchor_chain_and_lookup():
    g = GlobalAnchorLog()
    led = IndividualLedger(owner_id=b"user-A")
    led.append(commit(b"m0")[0])
    r1 = led.root
    rec1 = g.anchor(b"user-A", r1, drand_round=(1).to_bytes(8, "big"))
    led.append(commit(b"m1")[0])
    r2 = led.root
    g.anchor(b"user-A", r2, drand_round=(2).to_bytes(8, "big"))
    g.anchor(b"space-1", merkle.empty_root(), drand_round=(2).to_bytes(8, "big"))

    assert g.verify_chain()
    assert g.latest_root(b"user-A") == r2          # most recent
    assert g.is_anchored(b"user-A", r1)            # older root still recorded
    assert g.latest_root(b"unknown") is None
    assert rec1.prev_hash == GlobalAnchorLog.GENESIS


def test_global_anchor_is_tamper_evident():
    g = GlobalAnchorLog()
    g.anchor(b"A", random_bytes(32), (1).to_bytes(8, "big"))
    g.anchor(b"A", random_bytes(32), (2).to_bytes(8, "big"))
    # mutate a past anchored root -> chain no longer verifies
    object.__setattr__(g._entries[0], "anchored_root", random_bytes(32))
    assert not g.verify_chain()


def test_global_anchor_rejects_backdated_round():
    g = GlobalAnchorLog()
    g.anchor(b"A", random_bytes(32), (5).to_bytes(8, "big"))
    with pytest.raises(ValueError):
        g.anchor(b"A", random_bytes(32), (4).to_bytes(8, "big"))     # backdated -> rejected
    g.anchor(b"A", random_bytes(32), (5).to_bytes(8, "big"))         # same round is fine


def test_global_anchor_binds_the_drand_round():
    g1, g2 = GlobalAnchorLog(), GlobalAnchorLog()
    owner, root = b"A", random_bytes(32)
    e1 = g1.anchor(owner, root, (1).to_bytes(8, "big"))
    e2 = g2.anchor(owner, root, (2).to_bytes(8, "big"))
    assert e1.entry_hash != e2.entry_hash          # same owner+root, different time -> different


def test_verify_chain_rejects_rewound_rounds_even_when_hashes_are_consistent():
    # D2 fix: anchor() blocks backdating on append, but a producer can hand-build a chain whose
    # hashes/links/indices are all consistent yet whose drand rounds go BACKWARD. verify_chain()
    # (what a third party runs) must catch that too, else timestamp-rewind isn't self-verifying.
    from atlas.crypto.primitives import H
    from atlas.ledger.global_anchor import _GLOBAL, _lp, GlobalReceipt

    g = GlobalAnchorLog()
    e0 = g.anchor(b"A", random_bytes(32), (100).to_bytes(8, "big"))
    owner, root, lo = b"A", random_bytes(32), (50).to_bytes(8, "big")   # LOWER round
    eh = H(_GLOBAL, e0.entry_hash, _lp(owner), _lp(root), _lp(lo),
           (1).to_bytes(8, "big"))                                       # hash-consistent (new framing)
    g._entries.append(GlobalReceipt(index=1, owner_id=owner, anchored_root=root,
                                    drand_round=lo, entry_hash=eh, prev_hash=e0.entry_hash))
    assert not g.verify_chain()                    # rewound round rejected by the verifier


# --------------------------------------------------------------------------- #9 conversation
def test_accountable_commits_and_is_provable_later():
    led = IndividualLedger(owner_id=b"user-A")
    g = GlobalAnchorLog()
    assert is_anchored_mode(ConversationMode.ACCOUNTABLE)

    content = b"I agree to the terms."
    msg = record_message(led, ConversationMode.ACCOUNTABLE, content)
    assert isinstance(msg, AnchoredMessage) and len(led) == 1

    # anchor the root globally (only the root leaves the ledger)
    root = led.root
    g.anchor(led.owner_id, root, drand_round=(7).to_bytes(8, "big"))

    # later: prove this one message, revealing only it
    proof = prove_message(led, msg, content)
    assert proof.verify()
    assert g.is_anchored(led.owner_id, proof.inclusion.root)   # against the anchored root
    # a forged content does not verify
    bad = prove_message(led, msg, b"I never agreed.")
    assert not bad.verify()


def test_deniable_commits_nothing():
    led = IndividualLedger(owner_id=b"user-A")
    assert not is_anchored_mode(ConversationMode.DENIABLE)
    assert record_message(led, ConversationMode.DENIABLE, b"off the record") is None
    assert len(led) == 0 and led.root == merkle.empty_root()


def test_selective_disclosure_reveals_only_the_one_message():
    led = IndividualLedger(owner_id=b"user-A")
    msgs = [record_message(led, ConversationMode.ACCOUNTABLE, f"m{i}".encode()) for i in range(5)]
    proof = prove_message(led, msgs[2], b"m2")
    assert proof.verify()
    # the proof carries only message 2's content + opening; nothing of the other messages
    assert proof.content == b"m2" and proof.opening == msgs[2].opening
    for other in (0, 1, 3, 4):
        assert f"m{other}".encode() != proof.content
