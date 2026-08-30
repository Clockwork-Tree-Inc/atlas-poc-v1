"""Space kinds, persistence modes, and authority-based invitation — the Phase-B layer over the base
`spaces/space.py` vault primitive (PLATFORM_PLAN §3).

ONE substrate, many shapes. A Space is `{ kind, persistence, owner-authority-root, members }` hosted
in a vault. Every named shape (Self / Direct / Family / Friends / Movement / Host / Org / Commons) is
a CONSTRUCTOR over the same object — not a separate app.

Membership + roles ride the AUTHORITY engine (`atlas/authority`): the space OWNER is the resource's
**forward-secure authority root** (A13); inviting a member is an authority GRANT of a role, and a
member's role is whatever their grant chain verifies to. Permissions compose and don't leak upward
(the authority engine's invariants), so an admin can only invite within the rights they hold.

Persistence is ORTHOGONAL — any space can use any mode per message (the mode names the storage/witness
path). `PersistenceMode`'s int values are the escalation rank (least → most durable/witnessed).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Optional, Sequence

from ..authority import (
    AuthorityError, Caveat, FSPublicKey, FSSigner, Grant, RightSet, delegate, issue_fs, verify_chain,
)
from ..crypto.sign import HybridSigKeypair, HybridSigPublic


class SpaceKind(str, Enum):
    """LOCKED names (PLATFORM_PLAN §3). Do NOT reintroduce Hearth / Guild-as-room / Journal."""
    SELF = "self"          # journal; a space of one
    DIRECT = "direct"      # 1:1
    FAMILY = "family"      # free
    FRIENDS = "friends"    # your people; a Huddle is a group chat within Friends
    MOVEMENT = "movement"  # a seed that grows into site / newsletter / campaign; vault-hosted
    HOST = "host"          # mixed, admin-defined membership
    ORG = "org"            # organizational workspace
    COMMONS = "commons"    # public, Reddit-shaped; identity optional


class PersistenceMode(IntEnum):
    """LOCKED, orthogonal — any space, any mode. Value = escalation rank (least → most durable)."""
    PRESENT = 0   # live only, then gone — no stored copy
    FADING = 1    # user-set duration, then deleted
    PRIVATE = 2   # permanent; ledgered between the parties; provable by them
    PUBLIC = 3    # permanent; anchored to the global ledger; provable to anyone


# Persistence mode -> the storage / witness path it uses (from the existing primitives).
_BACKEND = {
    PersistenceMode.PRESENT: "blind-relay (no retention)",
    PersistenceMode.FADING: "relay / vault + TTL",
    PersistenceMode.PRIVATE: "IndividualLedger (between the parties)",
    PersistenceMode.PUBLIC: "GlobalAnchor (provable to anyone)",
}


def persistence_backend(mode: PersistenceMode) -> str:
    return _BACKEND[mode]


class Role(IntEnum):
    """Space role ladder — reused as the authority `RightSet` level for this resource type. Higher =
    more. Attenuation (a delegate can't exceed its delegator) is the authority engine's job."""
    NONE = 0
    GUEST = 1       # read
    MEMBER = 2      # post
    MODERATOR = 3   # moderate
    ADMIN = 4       # admin / invite
    OWNER = 5       # full control


class Access(IntEnum):
    """LOCKED — who may ENTER/POST (orthogonal to kind & persistence). The concentric rings, innermost
    → outermost. Determines the POSTING GATE, and with it whether moderation is allow-list or block-list:

      * SELF   — owner only. A space of one.
      * INVITE — closed group; you must hold an invite GRANT (allow-list, per-person). Direct/Family/Friends.
      * MEMBER — you must be admitted ONCE (hold a member grant), then post freely. Private commons / Org.
      * OPEN   — any VERIFIED HUMAN may post, no invite. Public commons / the town square. Moderation is
                 BLOCK-list (owner/mods BAN), not allow-list — personhood is the sybil gate, not an invite.
    """
    SELF = 0
    INVITE = 1
    MEMBER = 2
    OPEN = 3


# Default access per kind (user-overridable). Public/movement shapes open; groups invite-only.
_DEFAULT_ACCESS = {
    SpaceKind.SELF: Access.SELF,
    SpaceKind.DIRECT: Access.INVITE,
    SpaceKind.FAMILY: Access.INVITE,
    SpaceKind.FRIENDS: Access.INVITE,
    SpaceKind.MOVEMENT: Access.MEMBER,
    SpaceKind.HOST: Access.MEMBER,
    SpaceKind.ORG: Access.MEMBER,
    SpaceKind.COMMONS: Access.OPEN,
}


class IdentityTier(IntEnum):
    """LOCKED — the accountability a space demands of participants (orthogonal to kind/access/
    persistence). Rises from most-private to most-accountable; real-ID is never exposed even at the top.

      * ANONYMOUS       — no persistent identity required; ephemeral, unlinkable participation.
      * PSEUDONYMOUS    — a persistent pseudonym (no personhood check — one human may hold many).
      * VERIFIED_PERSON — a personhood-backed pseudonym: ONE per human (the sybil gate), accountable,
                          but the real legal identity stays hidden. Required by the market and by any
                          one-human-one-voice context. This is "accountable pseudonymity."
    """
    ANONYMOUS = 0
    PSEUDONYMOUS = 1
    VERIFIED_PERSON = 2


# Default identity per kind (user-overridable). Places default to pseudonymous; the public square is
# verified-person (sybil-resistant); anonymity is opt-in where a space wants it.
_DEFAULT_IDENTITY = {
    SpaceKind.SELF: IdentityTier.PSEUDONYMOUS,
    SpaceKind.DIRECT: IdentityTier.PSEUDONYMOUS,
    SpaceKind.FAMILY: IdentityTier.PSEUDONYMOUS,
    SpaceKind.FRIENDS: IdentityTier.PSEUDONYMOUS,
    SpaceKind.MOVEMENT: IdentityTier.PSEUDONYMOUS,
    SpaceKind.HOST: IdentityTier.PSEUDONYMOUS,
    SpaceKind.ORG: IdentityTier.PSEUDONYMOUS,
    SpaceKind.COMMONS: IdentityTier.VERIFIED_PERSON,
}


# Default persistence per kind (a hint — always user-overridable, since modes are orthogonal).
_DEFAULT_MODE = {
    SpaceKind.SELF: PersistenceMode.PRIVATE,
    SpaceKind.DIRECT: PersistenceMode.PRIVATE,
    SpaceKind.FAMILY: PersistenceMode.PRIVATE,
    SpaceKind.FRIENDS: PersistenceMode.PRIVATE,
    SpaceKind.MOVEMENT: PersistenceMode.PUBLIC,
    SpaceKind.HOST: PersistenceMode.PRIVATE,
    SpaceKind.ORG: PersistenceMode.PRIVATE,
    SpaceKind.COMMONS: PersistenceMode.PUBLIC,
}


@dataclass(frozen=True)
class SpaceDescriptor:
    """A space's public identity: its id, kind, default persistence, access tier, the OWNER's
    forward-secure authority root (against which membership grants verify), and the VAULT it lives in.
    Holds no secrets and no content.

    `vault_id` is the "real estate" linkage: your vault is your land, and a shop / game / forum you
    build is a sub-space *of* that vault (vault_id = the owning vault's id). A top-level vault has
    `vault_id is None` (it IS the land)."""

    space_id: bytes
    kind: SpaceKind
    owner_root: FSPublicKey
    persistence: PersistenceMode
    access: Access
    identity: IdentityTier
    vault_id: Optional[bytes] = None


def make_space(space_id: bytes, kind: SpaceKind, owner_root: FSPublicKey,
               persistence: Optional[PersistenceMode] = None, *,
               access: Optional[Access] = None, identity: Optional[IdentityTier] = None,
               vault_id: Optional[bytes] = None) -> SpaceDescriptor:
    """Construct a space of `kind`, owned (authority-rooted) by `owner_root`. `persistence`, `access`,
    and `identity` default per kind but are user-overridable (all orthogonal to kind). `vault_id` names
    the vault this space is built inside (None = a top-level vault / your land itself)."""
    # NB: PersistenceMode.PRESENT / Access.SELF / IdentityTier.ANONYMOUS are 0 (falsy) — test `is None`.
    mode = persistence if persistence is not None else _DEFAULT_MODE[kind]
    acc = access if access is not None else _DEFAULT_ACCESS[kind]
    ident = identity if identity is not None else _DEFAULT_IDENTITY[kind]
    return SpaceDescriptor(space_id=space_id, kind=kind, owner_root=owner_root, persistence=mode,
                           access=acc, identity=ident, vault_id=vault_id)


# --- named-shape constructors (all one primitive) ---------------------------
def self_space(space_id, owner_root, persistence=None):
    return make_space(space_id, SpaceKind.SELF, owner_root, persistence)


def direct(space_id, owner_root, persistence=None):
    return make_space(space_id, SpaceKind.DIRECT, owner_root, persistence)


def family(space_id, owner_root, persistence=None):
    return make_space(space_id, SpaceKind.FAMILY, owner_root, persistence)


def friends(space_id, owner_root, persistence=None):
    return make_space(space_id, SpaceKind.FRIENDS, owner_root, persistence)


def movement(space_id, owner_root, persistence=None):
    return make_space(space_id, SpaceKind.MOVEMENT, owner_root, persistence)


def host(space_id, owner_root, persistence=None):
    return make_space(space_id, SpaceKind.HOST, owner_root, persistence)


def org(space_id, owner_root, persistence=None):
    return make_space(space_id, SpaceKind.ORG, owner_root, persistence)


def commons(space_id, owner_root, persistence=None):
    return make_space(space_id, SpaceKind.COMMONS, owner_root, persistence)


# --- membership / invitation (rides the authority engine) -------------------
def invite(space: SpaceDescriptor, owner_signer: FSSigner, *, invitee: HybridSigPublic, role: Role,
           delegable: bool = False, caveats: Sequence[Caveat] = ()) -> Grant:
    """The OWNER invites `invitee` at `role` — a forward-secure authority ROOT grant scoped to this
    space. `delegable=True` lets the invitee re-invite (below their own role, per attenuation). Caveats
    (e.g. 'one channel') attach and can only accumulate downstream."""
    return issue_fs(owner_signer, grantee=invitee, resource=space.space_id,
                    rights=RightSet(int(role)), caveats=caveats,
                    delegable_depth=1 if delegable else 0)


def sub_invite(parent: Grant, holder_kp: HybridSigKeypair, *, invitee: HybridSigPublic, role: Role,
               add_caveats: Sequence[Caveat] = ()) -> Grant:
    """A member with a delegable grant invites `invitee` at `role` — MUST be <= the member's own role
    (authority attenuation rejects escalation)."""
    return delegate(parent, holder_kp, grantee=invitee, rights=RightSet(int(role)), add_caveats=add_caveats)


def member_role(space: SpaceDescriptor, chain: Sequence[Grant], *, now: int, **kw) -> Role:
    """The role a presented grant chain confers in this space (fail-closed via the authority engine —
    raises AuthorityError on any invalid chain). Verified against the space's forward-secure owner
    root, so backdating / escalation / cross-space grants are all rejected."""
    rights = verify_chain(chain, resource=space.space_id, resource_root=space.owner_root, now=now, **kw)
    return Role(rights.level)


def has_role(space: SpaceDescriptor, chain: Sequence[Grant], *, at_least: Role, now: int, **kw) -> bool:
    """Content-authorization gate: does `chain` confer at least `at_least` in this space? Fail-closed
    (any invalid chain -> False). E.g. posting requires `has_role(..., at_least=Role.MEMBER)`."""
    try:
        return int(member_role(space, chain, now=now, **kw)) >= int(at_least)
    except AuthorityError:
        return False
