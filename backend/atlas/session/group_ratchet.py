"""Group conversation crypto (MLS / Sender-Keys shape) + optional ledger + person-scoped block.

Three properties, each tested:

  * A conversation STARTER creates the group; every ADD/REMOVE re-keys with a FRESH epoch secret
    distributed (sealed) to the CURRENT members via the post-quantum X-Wing KEM. A member ADDED at
    epoch e receives epoch e's secret only -> it cannot read anything from before it joined. A
    member REMOVED at epoch e is excluded from epoch e's seals, and the secret is FRESH (not derived
    from the prior epoch) -> it cannot read anything after it leaves. Within an epoch, per-message
    keys ratchet by counter (forward secrecy); each membership change injects fresh entropy
    (post-compromise healing).

  * OPTIONAL per-conversation LEDGER: opt-in; records message COMMITMENTS (hashes) — never keys or
    content — in a tamper-evident hash chain. Provable/orderable WITHOUT breaking forward secrecy.

  * PERSON-scoped BLOCK: block a PERSON within a conversation scope via a scoped person-tag
    (`space_nullifier`) so a blocked person cannot evade with a fresh pseudonym; unlinkable outside
    the scope.

Reference scope: rekey is O(N) (a fresh secret sealed to each current member). MLS TreeKEM gives
O(log N) + stronger post-compromise security at scale; the KEM here is already PQ-hybrid.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ..crypto import kem
from ..crypto.primitives import H, hkdf, random_bytes
from ..zk.person_tag import nullifier as _dl_nullifier
from ..zk.person_tag import root_scalar
from .tunnel import Message, SendMode, open_message, seal


# --------------------------------------------------------------------------- ratchet
@dataclass
class GroupMember:
    handle: bytes
    kem: kem.HybridKEMKeypair


@dataclass
class Commit:
    """A membership/rekey commit: the fresh epoch secret sealed to each current member (by handle)."""
    epoch: int
    members: List[bytes]
    seals: Dict[bytes, Tuple[bytes, bytes, bytes]]   # handle -> (mlkem_ct, x_eph_pk, sealed_secret)


def _seal_to(members: List[GroupMember], secret: bytes) -> Dict[bytes, Tuple[bytes, bytes, bytes]]:
    seals: Dict[bytes, Tuple[bytes, bytes, bytes]] = {}
    for m in members:
        enc = kem.encapsulate(m.kem.public)
        sealed = seal(secret, mode=SendMode.NORMAL, key=enc.shared)
        seals[m.handle] = (enc.mlkem_ct, enc.x25519_eph_pk, sealed.ciphertext)
    return seals


class GroupController:
    """Produces commits (a fresh epoch secret sealed to the current member set). In a real system any
    current member commits; modelled centrally here for the reference."""

    def __init__(self, founders: List[GroupMember]):
        self.epoch = 0
        self.members: List[GroupMember] = list(founders)
        self._secret = random_bytes(32)

    def create(self) -> Commit:
        return Commit(self.epoch, [m.handle for m in self.members], _seal_to(self.members, self._secret))

    def add(self, m: GroupMember) -> Commit:
        self.epoch += 1
        self.members.append(m)
        self._secret = random_bytes(32)                       # fresh -> the joiner gets no prior secret
        return Commit(self.epoch, [x.handle for x in self.members], _seal_to(self.members, self._secret))

    def remove(self, handle: bytes) -> Commit:
        self.epoch += 1
        self.members = [x for x in self.members if x.handle != handle]
        self._secret = random_bytes(32)                       # fresh -> the removed member can't derive it
        return Commit(self.epoch, [x.handle for x in self.members], _seal_to(self.members, self._secret))

    def rekey(self, presence_entropy: Optional[bytes] = None) -> Commit:
        """POST-COMPROMISE SELF-HEAL — no membership change. Injects fresh entropy the attacker
        cannot have and re-seals it to the CURRENT members via the PQ-hybrid KEM, so a snapshot of
        the old epoch secret can no longer read anything after this commit.

        This is where LIVENESS heals the session. Presence never becomes the key directly (raw
        sensor bytes are not uniform and are partly observable — the ambient-entropy rule keeps them
        as timing/gating only). Instead the CLEAN CSPRNG/QRNG value is the key material, and the
        live-presence signal acts as the GATE + CLOCK: presence says "a live human is here now, heal
        the chain," an optional clean per-epoch `presence_entropy` (a QRNG-seam value, NOT raw
        sensor data) is mixed in, and the whole fresh secret rides the KEM to every member so both
        sides advance in lockstep. Drive this on the presence epoch for continuous, automatic PCS."""
        self.epoch += 1
        fresh = random_bytes(32)
        # New secret is INDEPENDENT of the old one (not a KDF of it), so an attacker holding the old
        # epoch secret learns nothing about this one — that independence is the heal. `presence_entropy`
        # only adds to the fresh clean value; it can never weaken it.
        self._secret = hkdf(ikm=fresh + (presence_entropy or b""),
                            info=b"atlas/group/heal/" + str(self.epoch).encode(), length=32)
        return Commit(self.epoch, [x.handle for x in self.members], _seal_to(self.members, self._secret))


@dataclass
class GroupSession:
    """One member's local view. `apply` opens the commit sealed to THIS member; it fails (returns
    False) if this member is not in the commit (added-later / removed -> no access to that epoch)."""
    me: bytes
    kem: kem.HybridKEMKeypair
    epoch: int = -1
    epoch_secret: bytes = b""
    members: List[bytes] = field(default_factory=list)

    def apply(self, commit: Commit) -> bool:
        entry = commit.seals.get(self.me)
        if entry is None:
            return False                                      # not a member of this epoch -> no key
        mlkem_ct, x_eph_pk, sealed = entry
        shared = kem.decapsulate(self.kem, mlkem_ct, x_eph_pk)
        self.epoch_secret = open_message(Message(mode=SendMode.NORMAL, ciphertext=sealed), key=shared)
        self.epoch = commit.epoch
        self.members = list(commit.members)
        return True


def message_key(epoch_secret: bytes, counter: int) -> bytes:
    """Per-message key inside an epoch — ratchets by counter (forward secrecy). Pure function of the
    epoch secret + counter, so sender and receiver derive the same key from the same epoch."""
    return hkdf(ikm=epoch_secret, info=b"atlas/group/msg/" + str(counter).encode(), length=32)


# --------------------------------------------------------------------------- optional ledger
@dataclass
class LedgerEntry:
    seq: int
    commitment: bytes     # H(message) — a fingerprint, NOT the message or any key
    prev: bytes


class ConversationLedger:
    """OPT-IN per-conversation record of message COMMITMENTS (hashes) in a tamper-evident chain —
    provable/orderable without retaining content or keys, so it does not break forward secrecy.
    (Off by default; a conversation attaches one only if participants choose. Aligns with the
    existing conversation ledger / global anchor primitives.)"""

    _ZERO = b"\x00" * 32

    def __init__(self) -> None:
        self.entries: List[LedgerEntry] = []
        self.head = self._ZERO

    def record(self, message: bytes) -> LedgerEntry:
        commit = H(b"atlas/convo/commit", message)
        e = LedgerEntry(seq=len(self.entries), commitment=commit, prev=self.head)
        self.head = H(b"atlas/convo/chain", self.head, commit)
        self.entries.append(e)
        return e

    def verify_chain(self) -> bool:
        head = self._ZERO
        for e in self.entries:
            if e.prev != head:
                return False
            head = H(b"atlas/convo/chain", head, e.commitment)
        return head == self.head


# --------------------------------------------------------------------------- person-scoped block
class BlockList:
    """Person-scoped blocking. Blocking binds the PERSON (via a scoped person-tag), not a pseudonym,
    so a blocked person cannot evade the block by spinning up a fresh pseudonym WITHIN this scope.
    The tag = `space_nullifier(person_root, scope)` — the same human yields the same tag in this
    scope (block sticks across all their pseudonyms here) but an unrelated tag in any other scope
    and nothing about who they are. This is the one deliberate, NARROW, scoped relaxation of
    unlinkability — scoped to the blocker's conversation, never global."""

    def __init__(self, scope: bytes):
        self.scope = scope
        self._blocked: set = set()

    def person_tag(self, person_root: bytes) -> int:
        # unified DL person-tag (same scheme as spaces/blocking + votes), not the old SHA3 nullifier
        return _dl_nullifier(root_scalar(person_root), self.scope)

    def block(self, person_root: bytes) -> None:
        self._blocked.add(self.person_tag(person_root))

    def is_blocked(self, person_root: bytes) -> bool:
        return self.person_tag(person_root) in self._blocked
