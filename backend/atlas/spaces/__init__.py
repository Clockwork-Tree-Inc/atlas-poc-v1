"""Group spaces (TRUST_LAYER.md #12) — personal/family/workplace self-hosted vaults.

A "space" is a group **threshold root** (k-of-n; the members ARE the n, joined under space-nyms
not their roots) + a presence-gated **ciphertext-only vault** + **reshare**-managed membership +
per-space **policy** (access threshold, governance threshold, tenant isolation). It is composition
over primitives that already exist — Shamir, the threshold seal, and per-space pseudonyms (#13) —
not new crypto. See `space.py`.

`kinds.py` layers the Phase-B taxonomy on top: the locked Space kinds (Self/Direct/Family/Friends/
Movement/Host/Org/Commons), the orthogonal persistence modes (Present/Fading/Private/Public), and
authority-based invitation (roles = grants; the owner is a forward-secure authority root).
"""

from .kinds import (
    Access,
    IdentityTier,
    PersistenceMode,
    Role,
    SpaceDescriptor,
    SpaceKind,
    commons,
    direct,
    family,
    friends,
    has_role,
    host,
    invite,
    make_space,
    member_role,
    movement,
    org,
    persistence_backend,
    self_space,
    sub_invite,
)

__all__ = [
    "Access", "IdentityTier", "PersistenceMode", "Role", "SpaceDescriptor", "SpaceKind",
    "commons", "direct", "family", "friends", "has_role", "host", "invite", "make_space",
    "member_role", "movement", "org", "persistence_backend", "self_space", "sub_invite",
]
