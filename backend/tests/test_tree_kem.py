"""TreeKEM ratchet tree: create/update/remove keep the group in sync on ONE secret; every commit
re-keys with fresh entropy (forward secrecy + post-compromise heal); a removed member cannot derive
the new secret; and a steady-state update is O(log N), not O(N)."""

from atlas.session.tree_kem import commit_remove, commit_update, new_group


def _populate(members):
    """Bring the tree to a fully-populated (steady) state so updates are O(log N)."""
    for idx in (0, len(members) - 1):
        c = commit_update(members[idx], members)
        for m in members:
            m.apply(c)


def test_create_shares_one_group_secret():
    ms = new_group(4)
    assert len({m.group_secret() for m in ms}) == 1     # all members agree on ONE group secret
    assert all(m.root_secret for m in ms)


def test_update_rekeys_and_keeps_everyone_in_sync_with_pcs():
    ms = new_group(4)
    before = ms[0].group_secret()
    c = commit_update(ms[2], ms)
    for m in ms:
        m.apply(c)
    after = {m.group_secret() for m in ms}
    assert len(after) == 1                               # still in sync
    assert before not in after                           # fresh secret (forward secrecy / PCS heal)


def test_steady_state_update_is_log_n():
    ms = new_group(4)          # depth 2
    _populate(ms)
    c = commit_update(ms[0], ms)
    assert c.ciphertext_count() == ms[0].depth           # one ciphertext per level = log2(4) = 2, not 4
    for m in ms:
        m.apply(c)
    assert len({m.group_secret() for m in ms}) == 1


def test_larger_group_update_is_log_n():
    ms = new_group(8)          # depth 3
    _populate(ms)
    # populate the two inner quarters too, so the whole tree is keyed
    for idx in (2, 5):
        c = commit_update(ms[idx], ms)
        for m in ms:
            m.apply(c)
    c = commit_update(ms[3], ms)
    assert c.ciphertext_count() == ms[0].depth           # 3 ciphertexts for N=8 (log N), not 8
    for m in ms:
        m.apply(c)
    assert len({m.group_secret() for m in ms}) == 1


def test_removed_member_cannot_derive_future_secret():
    ms = new_group(4)
    _populate(ms)
    removed = ms[1]
    old = removed.group_secret()
    c = commit_remove(ms[0], removed_leaf=1, members=ms)
    for m in ms:
        if m.index != 1:
            m.apply(c)
    remaining = {m.group_secret() for m in ms if m.index != 1}
    assert len(remaining) == 1                            # remaining members share a new secret
    assert old not in remaining                           # the removed member is excluded from it
    assert removed.group_secret() == old                  # its stale state is stuck at the old epoch
