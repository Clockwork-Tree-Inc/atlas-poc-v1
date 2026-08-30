"""TreeKEM ratchet tree — O(log N) group rekey with post-compromise security (the scale upgrade to
the O(N) group ratchet). PQ-hybrid: node keypairs are the X-Wing ML-KEM-768 + X25519 hybrid,
derived deterministically from path secrets (`kem.keypair_from_seed`).

Shape (a reference, faithful to RFC 9420 TreeKEM's core, not every edge case — see NOTE):
  * A left-balanced binary tree; members are leaves. Each node has a hybrid keypair (or is blank).
  * A member holds the PRIVATE keys of the nodes on its own direct path (leaf -> root).
  * UPDATE by member L: pick a fresh leaf secret, HKDF-ratchet a PATH SECRET up the direct path,
    derive each node's keypair from its path secret, and encrypt each path secret to the RESOLUTION
    of the copath node at that level. A member in that copath subtree decrypts the one path secret
    at its lowest common ancestor with L, then HKDF-ratchets UP to the root — deriving every shared
    node keypair and the new root secret. For a populated tree that's ONE ciphertext per level =
    O(log N). The group secret = HKDF(root path secret).
  * ADD: fill a blank leaf with the newcomer's key + a committer update -> the newcomer gets the
    current root secret only (no history). REMOVE: blank the leaf's path + a committer update ->
    the removed member is excluded from the fresh secrets (no future). Every commit re-keys with
    fresh entropy -> forward secrecy + post-compromise security (a compromised member is healed out
    at the next update touching the shared path).

NOTE (honest simplifications vs full RFC 9420): resolution recurses blanks down to non-blank
descendants (so `create` and freshly-blanked subtrees cost more than one ciphertext until
populated — steady-state updates are O(log N)); no unmerged-leaves bookkeeping; capacity is a fixed
power of two. The security properties (no-history/no-future/FS/PCS) and the O(log N) steady-state
cost hold; the wire format is not MLS-compatible.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ..crypto import kem
from ..crypto.primitives import H, hkdf, random_bytes
from .tunnel import Message, SendMode, open_message, seal

Node = Tuple[int, int]   # (level, index); level 0 = leaves, level `depth` = root


# --------------------------------------------------------------------------- tree math
def _depth(capacity: int) -> int:
    d = 0
    while (1 << d) < capacity:
        d += 1
    return d


def direct_path(leaf: int, depth: int) -> List[Node]:
    """Leaf up to root, inclusive: [(0,leaf),(1,leaf>>1),...,(depth,0)]."""
    return [(l, leaf >> l) for l in range(depth + 1)]


def sibling(node: Node) -> Node:
    l, i = node
    return (l, i ^ 1)


def _children(node: Node) -> Tuple[Node, Node]:
    l, i = node
    return (l - 1, 2 * i), (l - 1, 2 * i + 1)


def _path_secrets(leaf_secret: bytes, depth: int) -> List[bytes]:
    """s[0]=leaf_secret; s[l]=HKDF(s[l-1]) — the chain up the direct path."""
    s = [leaf_secret]
    for _ in range(depth):
        s.append(hkdf(ikm=s[-1], info=b"atlas/treekem/path", length=32))
    return s


# --------------------------------------------------------------------------- commit
@dataclass
class Commit:
    committer_leaf: int
    pub_updates: Dict[Node, kem.HybridKEMPublic]                 # new public keys along the committer's path
    blanks: List[Node]                                          # nodes blanked (e.g. a removed leaf's path)
    # for each copath level, the path secret sealed to each node in that copath's resolution.
    # value = (level, mlkem_ct, x_eph_pk, sealed): `level` is the direct-path level the sealed secret
    # belongs to (so a deep resolution node still ratchets from the right level).
    secrets: Dict[Node, Tuple[int, bytes, bytes, bytes]]

    def ciphertext_count(self) -> int:
        return len(self.secrets)


@dataclass
class Member:
    """One member's view: the shared public tree, the private keypairs on its own direct path, and
    the current root secret (the group secret is derived from it)."""
    index: int
    depth: int
    pub: Dict[Node, Optional[kem.HybridKEMPublic]]
    priv: Dict[Node, kem.HybridKEMKeypair] = field(default_factory=dict)
    root_secret: bytes = b""

    def group_secret(self) -> bytes:
        return hkdf(ikm=self.root_secret, info=b"atlas/treekem/group", length=32)

    # -- resolution: non-blank nodes covering a subtree (recurse into blanks to descendants) --
    def _resolution(self, node: Node) -> List[Node]:
        if self.pub.get(node) is not None:
            return [node]
        if node[0] == 0:
            return []                                          # a blank leaf covers nothing
        left, right = _children(node)
        return self._resolution(left) + self._resolution(right)

    def apply(self, commit: Commit) -> bool:
        """Apply a commit: refresh the public tree, then (if not the committer) decrypt the one path
        secret at the lowest copath node on our direct path and ratchet up to the new root secret."""
        for node, pk in commit.pub_updates.items():
            self.pub[node] = pk
        for node in commit.blanks:
            self.pub[node] = None
            self.priv.pop(node, None)

        if commit.committer_leaf == self.index:
            return True                                        # committer already holds its fresh path

        my_path = set(direct_path(self.index, self.depth))
        # find the copath node (a node on OUR path) that a secret was sealed to, lowest level first
        for node in sorted((n for n in commit.secrets if n in my_path), key=lambda n: n[0]):
            kp = self.priv.get(node)
            if kp is None:
                continue
            level, mlkem_ct, x_eph_pk, sealed = commit.secrets[node]
            shared = kem.decapsulate(kp, mlkem_ct, x_eph_pk)
            try:
                secret = open_message(Message(mode=SendMode.NORMAL, ciphertext=sealed), key=shared)
            except Exception:
                continue
            # `secret` is the path secret for direct-path level `level`; ratchet up to the root.
            s = secret
            for l in range(level, self.depth + 1):
                self.priv[(l, self.index >> l)] = kem.keypair_from_seed(s)
                if l < self.depth:
                    s = hkdf(ikm=s, info=b"atlas/treekem/path", length=32)
            self.root_secret = s
            return True
        return False


def _make_commit(committer: Member, members: List[Member]) -> Commit:
    """Build an update commit from `committer`: fresh path secrets, new node keypairs, and each path
    secret sealed to the resolution of the copath node at that level."""
    depth = committer.depth
    leaf_secret = random_bytes(32)
    s = _path_secrets(leaf_secret, depth)
    dp = direct_path(committer.index, depth)
    pub_updates: Dict[Node, kem.HybridKEMPublic] = {}
    for l, node in enumerate(dp):
        kp = kem.keypair_from_seed(s[l])
        committer.priv[node] = kp
        committer.pub[node] = kp.public
        pub_updates[node] = kp.public
    committer.root_secret = s[depth]

    secrets: Dict[Node, Tuple[bytes, bytes, bytes]] = {}
    for l in range(1, depth + 1):                              # for each internal node on the path
        cop = sibling(dp[l - 1])                               # the copath node whose subtree must learn s[l]
        for res in committer._resolution(cop):
            rpub = committer.pub[res]
            enc = kem.encapsulate(rpub)
            sealed = seal(s[l], mode=SendMode.NORMAL, key=enc.shared).ciphertext
            secrets[res] = (l, enc.mlkem_ct, enc.x25519_eph_pk, sealed)
    return Commit(committer_leaf=committer.index, pub_updates=pub_updates, blanks=[], secrets=secrets)


# --------------------------------------------------------------------------- group ops
def new_group(n: int) -> List[Member]:
    """Create an n-member group. Each member gets a leaf keypair; member 0 commits to establish the
    first epoch (populating its path and distributing the root secret to everyone)."""
    depth = _depth(n)
    leaves = [kem.generate_keypair() for _ in range(n)]
    pub: Dict[Node, Optional[kem.HybridKEMPublic]] = {}
    members: List[Member] = []
    for i in range(n):
        m = Member(index=i, depth=depth, pub=dict(pub))
        members.append(m)
    # everyone learns every leaf's PUBLIC key + holds its OWN leaf private
    for i in range(n):
        for m in members:
            m.pub[(0, i)] = leaves[i].public
        members[i].priv[(0, i)] = leaves[i]
    commit = _make_commit(members[0], members)
    for m in members:
        m.apply(commit)
    return members


def commit_update(committer: Member, members: List[Member]) -> Commit:
    """A member re-keys its path (post-compromise heal + fresh group secret)."""
    return _make_commit(committer, members)


def commit_remove(committer: Member, removed_leaf: int, members: List[Member]) -> Commit:
    """Blank the removed leaf's direct path, then the committer re-keys — the removed member is
    excluded from the fresh secrets, so it cannot derive the new group secret (no future)."""
    to_blank = direct_path(removed_leaf, committer.depth)[:-1]   # blank leaf..below-root on that path
    for m in members:
        for node in to_blank:
            if node not in direct_path(committer.index, committer.depth):
                m.pub[node] = None
                m.priv.pop(node, None)
    commit = _make_commit(committer, members)
    commit.blanks = [n for n in to_blank if n not in commit.pub_updates]
    return commit
