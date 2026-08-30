"""Space policy — the shared access substrate every vault sits on. A "folder" is a space; its
security is a POLICY on that space. Records assembly, the sensitive-records tier, anonymous-eligible
polls, and the vault all compose this one layer (see the entity/vault/Real-ID model).

One mechanism — MEMBERSHIP + ROLE, under POLICY — expresses everything discussed:
  * sharing a doc with a person   = add their handle as READER/CONTRIBUTOR
  * a business's officers         = GOVERNORs; changing the access set needs a governor QUORUM
  * an agent's leash              = a capability-scoped role; revoking = removing it
  * "independent read, joint governance" = READ is per-member; access CHANGES need M-of-N governors

Every access change is a QUORUM-authorized entry in an APPEND-ONLY, hash-chained log — which is both
the audit trail (retention ≠ readability; a coercer can't silently rewrite who-had-access) and the
sync source of truth (replay the log → both ends converge). `head()` is the anchorable digest:
signed-hash-chain by default; publish it to the drand beacon (or a public ledger) for third-party-
verifiable immutability — only the 32-byte head ever leaves, never content.

Revocation is FORWARD-ONLY (remove the role; rotate keys out of band) and always logged — honest,
the same as every crypto-sharing system. Not new crypto: HybridSig quorum over domain-separated,
length-prefixed bodies + a hash chain.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Sequence, Tuple

from ..crypto.primitives import H
from ..crypto.sign import HybridSigPublic, verify

_CHANGE = b"atlas/space-policy/change/v1"
_ENTRY = b"atlas/space-policy/entry/v1"
_GENESIS = b"atlas/space-policy/genesis/v1"


class PolicyError(Exception):
    pass


class NotAuthorized(PolicyError):
    """A change lacked a governor quorum, or an approver wasn't a current governor."""


class StaleChange(PolicyError):
    """The change was authorized against a different log head — someone else moved the chain."""


class Role(IntEnum):
    """Ordered capability levels — a higher role includes every lower capability."""
    READER = 1        # read space content
    CONTRIBUTOR = 2   # + add/update content
    GOVERNOR = 3      # + change the access set / policy (requires quorum)
    BREAK_GLASS = 4   # + emergency reveal of sealed material (always logged)


def _lp(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


@dataclass(frozen=True)
class Change:
    """A proposed mutation of the access set / policy. `target` is the affected member's public key
    (encoded); `role` is the new role for a grant (None for a revoke). `set_quorum` changes the
    governor threshold. Bound to `after_head` so it can only apply to the exact chain state it was
    approved against (no replay onto a moved chain)."""
    op: str                       # "grant" | "revoke" | "set_quorum"
    target: bytes                 # encoded HybridSigPublic (or b"" for set_quorum)
    role: int | None              # Role for grant, else None
    quorum: int | None            # new quorum for set_quorum, else None
    epoch: int
    after_head: bytes             # the log head this change extends

    def body(self) -> bytes:
        return b"".join([_CHANGE, _lp(self.op.encode()), _lp(self.target),
                         (int(self.role) if self.role is not None else 0).to_bytes(2, "big"),
                         (self.quorum if self.quorum is not None else 0).to_bytes(4, "big"),
                         self.epoch.to_bytes(8, "big"), _lp(self.after_head)])


@dataclass(frozen=True)
class LogEntry:
    seq: int
    prev_hash: bytes
    change_body: bytes
    approvers: Tuple[bytes, ...]   # encoded governor publics who authorized (genesis: the creator)
    entry_hash: bytes

    @staticmethod
    def compute_hash(prev_hash: bytes, change_body: bytes, approvers: Sequence[bytes]) -> bytes:
        parts = [_ENTRY, _lp(prev_hash), _lp(change_body), len(approvers).to_bytes(4, "big")]
        parts.extend(_lp(a) for a in approvers)
        return H(*parts)


@dataclass
class SpacePolicy:
    """The living access set + policy for one space, with its append-only authorization log."""
    space_id: bytes
    members: Dict[bytes, Role] = field(default_factory=dict)   # encoded public -> Role
    quorum: int = 1                                            # governor approvals to mutate access
    log: List[LogEntry] = field(default_factory=list)

    # ---- construction ------------------------------------------------------
    @classmethod
    def genesis(cls, space_id: bytes, creator: HybridSigPublic, *, epoch: int = 0) -> "SpacePolicy":
        """Create a space. The creator (an enrolled individual) is the first GOVERNOR, quorum=1.
        The genesis entry roots the hash chain; there is no prior head to approve against."""
        p = cls(space_id=space_id, members={creator.encode(): Role.GOVERNOR}, quorum=1)
        gbody = H(_GENESIS, _lp(space_id), _lp(creator.encode()), epoch.to_bytes(8, "big"))
        entry = LogEntry(seq=0, prev_hash=b"", change_body=gbody,
                         approvers=(creator.encode(),),
                         entry_hash=LogEntry.compute_hash(b"", gbody, (creator.encode(),)))
        p.log.append(entry)
        return p

    # ---- reads -------------------------------------------------------------
    def head(self) -> bytes:
        return self.log[-1].entry_hash if self.log else b""

    def role_of(self, member: HybridSigPublic) -> Role | None:
        return self.members.get(member.encode())

    def can(self, member: HybridSigPublic, capability: Role) -> bool:
        """Read is per-member and independent; higher capabilities need the matching role."""
        r = self.members.get(member.encode())
        return r is not None and r >= capability

    def governors(self) -> set[bytes]:
        return {h for h, r in self.members.items() if r >= Role.GOVERNOR}

    def members_at(self, minimum: Role) -> list[bytes]:
        """Encoded publics of members at or above `minimum` — the basis for a poll's eligible set."""
        return [h for h, r in self.members.items() if r >= minimum]

    # ---- proposals + authorization ----------------------------------------
    def propose(self, op: str, *, target: HybridSigPublic | None = None,
                role: Role | None = None, quorum: int | None = None, epoch: int) -> Change:
        if op not in ("grant", "revoke", "set_quorum"):
            raise PolicyError(f"unknown op {op!r}")
        return Change(op=op, target=target.encode() if target else b"",
                      role=int(role) if role is not None else None,
                      quorum=quorum, epoch=epoch, after_head=self.head())

    def authorize(self, change: Change,
                  approvals: Sequence[Tuple[HybridSigPublic, bytes]]) -> LogEntry:
        """Apply `change` iff ≥ quorum DISTINCT current governors signed it over the current head.
        Appends a hash-chained, signed log entry and mutates the access set. Idempotent replay is
        rejected via `after_head` (a change approved against an old head is stale)."""
        if change.after_head != self.head():
            raise StaleChange("change was approved against a different log head")

        body = change.body()
        gov = self.governors()
        seen: set[bytes] = set()
        for pub, sig in approvals:
            enc = pub.encode()
            if enc in gov and enc not in seen and verify(pub, body, sig):
                seen.add(enc)
        if len(seen) < self.quorum:
            raise NotAuthorized(f"need {self.quorum} governor approvals, got {len(seen)}")

        # apply
        if change.op == "grant":
            if change.role is None:
                raise PolicyError("grant needs a role")
            self.members[change.target] = Role(change.role)
        elif change.op == "revoke":
            self.members.pop(change.target, None)          # forward-only; history stays in the log
        elif change.op == "set_quorum":
            if change.quorum is None or change.quorum < 1:
                raise PolicyError("set_quorum needs quorum >= 1")
            if change.quorum > len(self.governors()):
                raise PolicyError("quorum cannot exceed the number of governors")
            self.quorum = change.quorum

        approvers = tuple(sorted(seen))
        entry = LogEntry(seq=len(self.log), prev_hash=self.head(), change_body=body,
                         approvers=approvers,
                         entry_hash=LogEntry.compute_hash(self.head(), body, approvers))
        self.log.append(entry)
        return entry

    # ---- audit -------------------------------------------------------------
    def verify_log(self) -> bool:
        """Recompute the hash chain end-to-end — any silent edit to a past entry breaks it."""
        prev = b""
        for i, e in enumerate(self.log):
            if e.seq != i or e.prev_hash != prev:
                return False
            if e.entry_hash != LogEntry.compute_hash(e.prev_hash, e.change_body, e.approvers):
                return False
            prev = e.entry_hash
        return True
