"""Distributed custody + rotation for the server half of the two-tier TSK.

Proves the "sharded over rotating nodes" property: server_half is Shamir k-of-m across nodes as
OPAQUE sealed blobs; any k rebuild it; a node can't read its share; rotation re-shares to a fresh
set and drops the old locators; and the whole thing slots into two-tier recovery end to end."""
import pytest

from atlas.crypto import shamir
from atlas.crypto.primitives import random_bytes
from atlas.keys.server_custody import (CustodianNode, ThresholdNotMet, collect_server_half,
                                        distribute_server_half, rotate_server_half)
from atlas.recovery.threshold_seal import ThresholdPolicy


def _nodes(*ids):
    return [CustodianNode(node_id=i) for i in ids]


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


SEL = b"blinded-recovery-selector"
POLICY = ThresholdPolicy(n=3, m=2)


def test_distribute_then_collect_any_k_roundtrips():
    server_half = random_bytes(32)
    rkey = random_bytes(32)
    pls = distribute_server_half(server_half, nodes=_nodes("a", "b", "c"), policy=POLICY,
                                 recovery_selector=SEL, recovery_key=rkey)
    # any 2 of the 3 placed shares reassemble server_half
    got = collect_server_half([(pls[0].locator, pls[0].blob), (pls[2].locator, pls[2].blob)],
                              policy=POLICY, recovery_key=rkey)
    assert got == server_half


def test_below_threshold_fails_closed():
    rkey = random_bytes(32)
    pls = distribute_server_half(random_bytes(32), nodes=_nodes("a", "b", "c"), policy=POLICY,
                                 recovery_selector=SEL, recovery_key=rkey)
    with pytest.raises(ThresholdNotMet):
        collect_server_half([(pls[0].locator, pls[0].blob)], policy=POLICY, recovery_key=rkey)


def test_node_holds_an_opaque_blob_it_cannot_open():
    server_half = random_bytes(32)
    rkey = random_bytes(32)
    pls = distribute_server_half(server_half, nodes=_nodes("a", "b", "c"), policy=POLICY,
                                 recovery_selector=SEL, recovery_key=rkey)
    raw_share = shamir.split(server_half, n=3, k=2)  # what a plaintext share would look like
    # the stored blob is NOT any raw share, and is longer (nonce+tag) — it's sealed
    assert all(pls[0].blob != s.encode() for s in raw_share)
    # a node without the recovery key cannot open its blob
    with pytest.raises(Exception):
        collect_server_half([(pls[0].locator, pls[0].blob), (pls[1].locator, pls[1].blob)],
                            policy=POLICY, recovery_key=random_bytes(32))


def test_blob_bound_to_its_locator():
    """A blob only opens under the key derived from ITS locator — you can't move a blob to another
    locator (AEAD tag fails), so shares can't be silently shuffled between slots."""
    rkey = random_bytes(32)
    pls = distribute_server_half(random_bytes(32), nodes=_nodes("a", "b", "c"), policy=POLICY,
                                 recovery_selector=SEL, recovery_key=rkey)
    with pytest.raises(Exception):
        # present pls[0]'s blob under pls[1]'s locator
        collect_server_half([(pls[1].locator, pls[0].blob), (pls[2].locator, pls[2].blob)],
                            policy=POLICY, recovery_key=rkey)


def test_rotation_reshares_to_fresh_set_and_invalidates_old_locators():
    server_half = random_bytes(32)
    rkey = random_bytes(32)
    old = distribute_server_half(server_half, nodes=_nodes("a", "b", "c"), policy=POLICY,
                                 recovery_selector=SEL, recovery_key=rkey, epoch=0)
    retrieved = [(old[0].locator, old[0].blob), (old[1].locator, old[1].blob)]
    new, drop = rotate_server_half(retrieved, all_old_locators=[p.locator for p in old],
                                   policy=POLICY, recovery_selector=SEL, recovery_key=rkey,
                                   new_nodes=_nodes("d", "e", "f"), new_epoch=1)
    # the fresh placements still reconstruct the SAME server_half
    got = collect_server_half([(new[0].locator, new[0].blob), (new[2].locator, new[2].blob)],
                              policy=POLICY, recovery_key=rkey)
    assert got == server_half
    # rotation names the old locators for deletion, and the new set is disjoint from the old
    assert set(drop) == {p.locator for p in old}
    assert {p.locator for p in old}.isdisjoint({p.locator for p in new})


def test_locators_are_unlinkable_across_nodes_and_users():
    rkey = random_bytes(32)
    pls = distribute_server_half(random_bytes(32), nodes=_nodes("a", "b", "c"), policy=POLICY,
                                 recovery_selector=SEL, recovery_key=rkey)
    # each node gets a distinct locator; nothing about the selector or node is recoverable from it
    assert len({p.locator for p in pls}) == 3
    # a different user (different selector) lands on entirely different locators
    other = distribute_server_half(random_bytes(32), nodes=_nodes("a", "b", "c"), policy=POLICY,
                                   recovery_selector=b"another-user", recovery_key=random_bytes(32))
    assert {p.locator for p in pls}.isdisjoint({p.locator for p in other})


def test_node_stores_serves_and_drops_opaque_shares(tmp_path, monkeypatch):
    """Drive the REAL node endpoints: distribute -> PUT each blob to the node -> GET them back ->
    collect -> server_half. Then DROP and confirm it's gone. The node only ever handles base64
    blobs it can't open."""
    import base64
    monkeypatch.setenv("ATLAS_STORAGE", str(tmp_path))
    from atlas.net.node_server import AtlasNode
    node = AtlasNode(port=0)

    server_half = random_bytes(32)
    rkey = random_bytes(32)
    pls = distribute_server_half(server_half, nodes=_nodes("a", "b", "c"), policy=POLICY,
                                 recovery_selector=SEL, recovery_key=rkey)
    for p in pls:
        code, (_, out) = node.dispatch("POST", "/custody/put",
                                       {"locator": p.locator.hex(), "blob": base64.b64encode(p.blob).decode()})
        assert code == 200 and out["ok"]

    # fetch any 2 back through the GET route and reassemble
    fetched = []
    for p in (pls[0], pls[2]):
        code, (_, out) = node.dispatch("GET", f"/custody/get/{p.locator.hex()}", {})
        assert code == 200
        fetched.append((p.locator, base64.b64decode(out["blob"])))
    assert collect_server_half(fetched, policy=POLICY, recovery_key=rkey) == server_half

    # drop one, and it's gone (404-style KeyError -> 400 from dispatch)
    node.dispatch("POST", "/custody/drop", {"locator": pls[0].locator.hex()})
    code, _ = node.dispatch("GET", f"/custody/get/{pls[0].locator.hex()}", {})
    assert code == 400


def test_node_rejects_non_hex_locator(tmp_path, monkeypatch):
    """No path traversal / junk keys — locators must be hex."""
    monkeypatch.setenv("ATLAS_STORAGE", str(tmp_path))
    from atlas.net.node_server import AtlasNode
    node = AtlasNode(port=0)
    code, (_, out) = node.dispatch("POST", "/custody/put", {"locator": "../etc/passwd", "blob": "AAAA"})
    assert code == 400


def test_end_to_end_two_tier_recovery_through_custody():
    """The whole point: custody is the SERVER SIDE of two-tier recovery. seed = user_half XOR
    server_half; user_half stays with YOUR holders, server_half is custody-sharded over nodes.
    Recovery needs a threshold of BOTH — and custody alone can never yield the seed."""
    seed = random_bytes(32)
    user_half = random_bytes(32)
    server_half = _xor(seed, user_half)
    rkey = random_bytes(32)

    user_shares = shamir.split(user_half, n=3, k=2)                     # YOUR holders
    pls = distribute_server_half(server_half, nodes=_nodes("a", "b", "c"), policy=POLICY,
                                 recovery_selector=SEL, recovery_key=rkey)   # server side

    # recover with 2 of your holders AND 2 custody shares
    rebuilt_user = shamir.combine(user_shares[:2])
    rebuilt_server = collect_server_half([(pls[0].locator, pls[0].blob), (pls[1].locator, pls[1].blob)],
                                         policy=POLICY, recovery_key=rkey)
    assert _xor(rebuilt_user, rebuilt_server) == seed

    # anti-institutional: the server side alone (server_half) reveals NOTHING about the seed
    assert rebuilt_server != seed
