"""Forward-secure ratcheted signer — the root signer that closes A13 structurally.

ONE fixed public key (a Merkle root over N per-epoch leaf keys). The signer holds only the CURRENT
epoch's state; `advance()` ratchets one-way (H) and DESTROYS the past — so a compromised *current*
signer cannot reconstruct a *past* epoch's secret to backdate a grant. A13 dies by construction: no
epoch-field check, no per-grant ledger lookup.

Design (reference):
  * state chain (forward-secret):   state_0 = H(genesis);  state_{t+1} = H(state_t)   [one-way]
  * per-epoch leaf key:              leaf_kp_t = keypair_from_seed(H(state_t))         [full HybridSig]
  * public key:                      Merkle root over H(leaf_pub_t) for t in 0..N-1
  * signature at epoch t:            (t, leaf_pub_t, HybridSig-sig by leaf_t, Merkle auth path)
  * verify:                          leaf sig valid  AND  auth path(leaf, t) hashes to the root

Each leaf is a FULL signature key (not a one-time key), so ONE epoch can sign MANY grants. Forward
security comes from the one-way state chain + destroying past leaf secrets — not from one-time-ness.

Because the signer at epoch t holds only `state_t` (past states are gone, `H` is one-way), it can
sign the current epoch but can NEVER re-derive an earlier epoch's leaf key. That is the whole point.

REFERENCE POSTURE: this models the forward-secure property with vetted per-leaf signatures + a Merkle
commitment. Production uses a PQ-native stateful hash-based signature (XMSS / LMS, NIST SP 800-208) —
same security argument (Merkle tree of one-time keys, state only advances). Cadence is a deployment
policy: default coarse + drand-aligned (e.g. one epoch/day), tunable per root; sub-epoch precision is
the ledger anchor's job, and ACTUAL current-key compromise is handled by a ledger-anchored re-root.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from ..crypto.primitives import H
from ..crypto.sign import HybridSigPublic, keypair_from_seed, sign, verify


class FSError(Exception):
    """Forward-secure signer failure (exhausted / invalid)."""


def _leaf_seed(state: bytes) -> bytes:
    return H(b"atlas/fs/leaf-seed", state)


def _next_state(state: bytes) -> bytes:
    return H(b"atlas/fs/state-next", state)


def _leaf_hash(leaf_pub_enc: bytes) -> bytes:
    return H(b"atlas/fs/leaf", leaf_pub_enc)


def _node(left: bytes, right: bytes) -> bytes:
    return H(b"atlas/fs/node", left, right)


# --------------------------------------------------------------------------- public key + signature
@dataclass(frozen=True)
class FSPublicKey:
    """The fixed forward-secure public key: a Merkle root over the N = 2**height epoch leaves."""

    root: bytes
    height: int


@dataclass(frozen=True)
class FSSignature:
    epoch: int
    leaf_public: bytes        # encoded HybridSigPublic of the epoch-t leaf
    sig: bytes                # HybridSig signature by the leaf over the message
    auth_path: List[bytes]    # sibling hashes, leaf -> root (length == height)


# --------------------------------------------------------------------------- merkle helpers
def _levels(leaf_hashes: List[bytes]) -> List[List[bytes]]:
    """Full tree as a list of levels; levels[0] = leaf hashes, levels[-1] = [root]."""
    levels = [leaf_hashes]
    cur = leaf_hashes
    while len(cur) > 1:
        cur = [_node(cur[i], cur[i + 1]) for i in range(0, len(cur), 2)]
        levels.append(cur)
    return levels


def _auth_path(levels: List[List[bytes]], index: int) -> List[bytes]:
    path, idx = [], index
    for level in levels[:-1]:
        path.append(level[idx ^ 1])
        idx //= 2
    return path


def _root_from_path(leaf_hash: bytes, index: int, path: List[bytes]) -> bytes:
    h, idx = leaf_hash, index
    for sib in path:
        h = _node(h, sib) if idx & 1 == 0 else _node(sib, h)
        idx //= 2
    return h


# --------------------------------------------------------------------------- signer
@dataclass
class FSSigner:
    """Stateful forward-secure signer. Holds ONLY the current epoch state (`_state`) — advancing
    destroys it one-way. `_levels` is the PUBLIC Merkle tree (leaf hashes are H(public); no secrets)."""

    _levels: List[List[bytes]] = field(repr=False)
    _n: int
    _index: int = 0
    _state: bytes = field(repr=False, default=b"")

    @property
    def epoch(self) -> int:
        return self._index

    def public_key(self) -> FSPublicKey:
        height = len(self._levels) - 1
        return FSPublicKey(root=self._levels[-1][0], height=height)

    def sign(self, message: bytes) -> FSSignature:
        """Sign at the CURRENT epoch. May be called many times per epoch (leaf is a full key)."""
        if self._index >= self._n:
            raise FSError("forward-secure signer exhausted (all epochs used) — re-root")
        leaf_kp = keypair_from_seed(_leaf_seed(self._state))
        return FSSignature(epoch=self._index, leaf_public=leaf_kp.public.encode(),
                           sig=sign(leaf_kp, message), auth_path=_auth_path(self._levels, self._index))

    def advance(self) -> None:
        """Ratchet to the next epoch, DESTROYING the current secret state (forward security)."""
        if self._index >= self._n:
            raise FSError("cannot advance past the last epoch — re-root")
        self._state = _next_state(self._state)     # one-way: state_t is now unrecoverable
        self._index += 1


def fs_keygen(seed: bytes, *, height: int = 4) -> tuple[FSPublicKey, FSSigner]:
    """Genesis: build the tree over N = 2**height epoch leaves and return (public key, signer at
    epoch 0). The genesis seed is consumed here; the signer retains only state_0 and the public tree."""
    if height < 1:
        raise FSError("height must be >= 1")
    n = 1 << height
    state = H(b"atlas/fs/genesis", seed)
    genesis_state = state
    leaf_hashes: List[bytes] = []
    for _ in range(n):
        leaf_pub = keypair_from_seed(_leaf_seed(state)).public.encode()
        leaf_hashes.append(_leaf_hash(leaf_pub))
        state = _next_state(state)
    levels = _levels(leaf_hashes)
    signer = FSSigner(_levels=levels, _n=n, _index=0, _state=genesis_state)
    return signer.public_key(), signer


def fs_verify(pub: FSPublicKey, message: bytes, signature: FSSignature) -> bool:
    """Verify a forward-secure signature: the leaf's HybridSig signature is valid AND the leaf, at
    the claimed epoch index, hashes up the auth path to the fixed public root. The epoch is INTRINSIC
    (bound by the auth-path position) — it is not a self-asserted field a signer can move."""
    n = 1 << pub.height
    if not (0 <= signature.epoch < n):
        return False
    if len(signature.auth_path) != pub.height:
        return False
    try:
        leaf_pub = HybridSigPublic.decode(signature.leaf_public)
    except Exception:
        return False
    if not verify(leaf_pub, message, signature.sig):
        return False
    leaf_hash = _leaf_hash(signature.leaf_public)
    return _root_from_path(leaf_hash, signature.epoch, signature.auth_path) == pub.root
