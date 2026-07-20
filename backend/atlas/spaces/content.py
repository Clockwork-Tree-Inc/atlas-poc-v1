"""Space content + persistence (Phase B, increment 2). A post is content authored by a MEMBER
(role-gated via the authority engine), committed by hash, and witnessed per the space's persistence
mode — composing the primitives that already exist, not new crypto.

Persistence modes (orthogonal; escalation Present → Fading → Private → Public):

  * PRESENT — live only; NO stored copy. The item exists in the moment; nothing is recorded.
  * FADING  — stored with an expiry epoch; pruned once `now` passes it.
  * PRIVATE — the commitment is appended to the space's IndividualLedger; provable BY THE PARTIES
              (inclusion proof against a root they share), not to the world.
  * PUBLIC  — additionally anchors the ledger root to the GlobalAnchorLog; provable to ANYONE.

Content confidentiality (sealing the bytes) is the existing `spaces/space.py` vault; this module is
the durability/witness layer over the commitment.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence

from ..crypto.primitives import H
from ..ledger.global_anchor import GlobalAnchorLog
from ..ledger.individual import IndividualLedger
from .kinds import Access, IdentityTier, PersistenceMode, Role, SpaceDescriptor, has_role


class AccessError(Exception):
    """Posting was refused — the author failed this space's access gate (fail-closed)."""


@dataclass(frozen=True)
class Ban:
    """A moderation record: `target` (a persona handle) is barred from an OPEN space. Honored only
    when issued by a MODERATOR+ (enforced in `SpaceStore.ban`). Block-list moderation — the inverse of
    an invite: OPEN spaces admit everyone verified, then remove abusers, rather than admitting per-person."""

    space_id: bytes
    target: bytes
    epoch: int


def content_commitment(space_id: bytes, author: bytes, content: bytes, parent: bytes = b"") -> bytes:
    """The public commitment to a post: binds the space, the author handle, the content, and (for a
    comment/reply) the `parent` item it hangs under. `parent=b""` for a top-level post."""
    return H(b"atlas/space-item", space_id, author, content, parent)


@dataclass(frozen=True)
class SpaceItem:
    space_id: bytes
    author: bytes                 # persona handle (opaque)
    content_hash: bytes
    persistence: PersistenceMode
    seq: int
    expiry: Optional[int] = None  # set only for FADING
    parent: Optional[bytes] = None  # content_hash of the item this replies to (None = top-level post)


class SpaceStore:
    """Content store for ONE space. Dispatches by persistence mode over the existing ledgers. Holds
    commitments + metadata only — the content bytes are sealed in the space vault elsewhere."""

    def __init__(self, space: SpaceDescriptor, *, global_anchor: Optional[GlobalAnchorLog] = None,
                 is_verified_human: Optional[Callable[[bytes], bool]] = None):
        self.space = space
        self.ledger = IndividualLedger(owner_id=space.space_id)   # PRIVATE / PUBLIC records
        self.global_anchor = global_anchor                        # shared; required for PUBLIC
        # OPEN spaces gate posting on VERIFIED-HUMANNESS (the sybil defense) instead of an invite. The
        # predicate is keyed by author handle; without it, OPEN posting is fail-closed (nobody passes).
        self.is_verified_human = is_verified_human
        self._banned: set = set()                                 # persona handles barred (block-list)
        self._items: List[SpaceItem] = []
        self._seq = 0

    def ban(self, mod_chain: Sequence, target: bytes, *, now: int, epoch: int = 0) -> Ban:
        """MODERATE an OPEN space by BLOCK-list: bar `target` from posting. Authorized only for a
        MODERATOR+ (fail-closed via the authority engine) — a random persona can't ban a rival."""
        if not has_role(self.space, mod_chain, at_least=Role.MODERATOR, now=now):
            raise AccessError("banning requires >= MODERATOR")
        self._banned.add(target)
        return Ban(space_id=self.space.space_id, target=target, epoch=epoch)

    def _gate(self, author_chain, author: bytes, now: int) -> None:
        """Fail-closed posting gate: TWO orthogonal checks — ACCESS (who may enter) then IDENTITY
        (what accountability the space demands)."""
        access = self.space.access
        # 1) ACCESS — the concentric rings.
        if access == Access.OPEN:
            if author in self._banned:                        # public square: block-list moderation
                raise AccessError("author is banned from this space")
        elif access == Access.SELF:
            if not has_role(self.space, author_chain, at_least=Role.OWNER, now=now):
                raise AccessError("SELF space: only the owner may post")
        else:                                                 # INVITE / MEMBER: allow-list
            if not has_role(self.space, author_chain, at_least=Role.MEMBER, now=now):
                raise AccessError("author needs >= MEMBER to post")

        # 2) IDENTITY — the accountability tier (orthogonal to access).
        identity = self.space.identity
        if identity == IdentityTier.VERIFIED_PERSON:
            # one-human-one-voice sybil gate — a personhood-backed pseudonym is required.
            if self.is_verified_human is None or not self.is_verified_human(author):
                raise AccessError("this space requires a verified-person identity")
        elif identity == IdentityTier.PSEUDONYMOUS:
            if not author:                                    # a persistent pseudonym (any handle)
                raise AccessError("this space requires a pseudonym")
        # IdentityTier.ANONYMOUS — no identity requirement.

    def post(self, author_chain, author: bytes, *, content: bytes, now: int,
             persistence: Optional[PersistenceMode] = None, ttl: Optional[int] = None,
             parent: Optional[bytes] = None) -> SpaceItem:
        """Author a post — or, when `parent` is the content_hash of another item, a COMMENT/reply that
        threads under it (a comment is just a post with a parent; same access gate, same persistence).
        The gate depends on the space's ACCESS tier (SELF / INVITE / MEMBER = allow-list via the
        authority engine; OPEN = verified-human + not-banned)."""
        self._gate(author_chain, author, now)
        mode = persistence if persistence is not None else self.space.persistence
        commit = content_commitment(self.space.space_id, author, content, parent or b"")
        self._seq += 1
        expiry = (now + ttl) if (mode == PersistenceMode.FADING and ttl is not None) else None
        item = SpaceItem(space_id=self.space.space_id, author=author, content_hash=commit,
                         persistence=mode, seq=self._seq, expiry=expiry, parent=parent)

        if mode == PersistenceMode.PRESENT:
            pass                                              # live only — nothing stored
        elif mode == PersistenceMode.FADING:
            self._items.append(item)                          # stored; pruned in `live()`
        else:                                                 # PRIVATE or PUBLIC
            self.ledger.append(commit)                        # ledgered between the parties
            self._items.append(item)
            if mode == PersistenceMode.PUBLIC:
                if self.global_anchor is None:
                    raise AccessError("PUBLIC persistence requires a global anchor")
                self.global_anchor.anchor(self.space.space_id, self.ledger.root,
                                          drand_round=now.to_bytes(8, "big"))
        return item

    def live(self, now: int) -> List[SpaceItem]:
        """Currently-live items — FADING items past their expiry are pruned."""
        return [it for it in self._items if it.expiry is None or now <= it.expiry]

    def replies(self, parent: bytes) -> List[SpaceItem]:
        """The comments/replies threaded directly under `parent` (its content_hash), in post order."""
        return [it for it in self._items if it.parent == parent]

    def is_publicly_provable(self) -> bool:
        """Was the current ledger root anchored to the global log (provable to anyone)?"""
        return (self.global_anchor is not None
                and self.global_anchor.is_anchored(self.space.space_id, self.ledger.root))
