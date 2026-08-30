"""The relay mailbox is an OPAQUE per-persona pseudonym, not a human-chosen name —
so it can't be used to read a person's identity or link their personas."""

import os

from atlas.keys.identity import build_identity_tree
from atlas.net.node_server import mailbox_for


def test_mailbox_is_opaque_and_per_persona_unlinkable():
    tree = build_identity_tree(os.urandom(32))
    shop = tree.profile("public-shop")
    anon = tree.profile("anon-1")
    m_shop, m_anon = mailbox_for(shop), mailbox_for(anon)

    # opaque: a hex handle, never the human-chosen label
    assert m_shop != "public-shop"
    assert len(m_shop) == 64 and all(c in "0123456789abcdef" for c in m_shop)

    # deterministic per persona (peers can address it across sessions)
    assert mailbox_for(tree.profile("public-shop")) == m_shop

    # two personas of the SAME human get UNLINKABLE mailboxes
    assert m_shop != m_anon

    # two DIFFERENT humans differ too
    other = build_identity_tree(os.urandom(32)).profile("public-shop")
    assert mailbox_for(other) != m_shop
