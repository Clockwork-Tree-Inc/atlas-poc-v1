"""Group spaces (TRUST_LAYER.md #12).

A space is a k-of-n threshold root shared among its members. Members join under a **space-nym**
(#13), never their root, so cross-space identities stay unlinkable. The space's **vault key** is
derived from the (threshold-reconstructed) space root, namespaced by `space_id` — so each space is
a separate tenant with its own keyspace. Two thresholds:

  * ACCESS threshold — how many members must be present to open the vault.
  * GOVERNANCE threshold — how many members must authorize adding/removing a member.

Membership changes **reshare** the SAME space root to the new member set (old shares invalidated,
the root — and therefore the vault contents — unchanged). The self-hosted store holds only
CIPHERTEXT and public roster/policy: it never holds the root, any share, or plaintext.

MODEL NOTE: this reference reconstructs the space root (from ≥k shares) to derive the vault key,
which is the PoC simplification of true threshold decryption; the security *properties* (no single
holder, k-of-n, reshare-preserves-secret, tenant isolation) are what the tests pin. Presence is
modelled as "a member contributes their share" (a present member does).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Sequence

from ..crypto import shamir
from ..crypto.primitives import aead_decrypt, aead_encrypt, hkdf, random_bytes
from ..realid.space_pseudonym import join_space

_VAULT = b"atlas/space-vault"


class SpaceError(Exception):
    pass


class GovernanceError(SpaceError):
    """Fewer authorizing shares than the governance threshold — the change is refused."""


class AccessError(SpaceError):
    """Fewer present shares than the access threshold — the vault stays closed."""


@dataclass(frozen=True)
class SpacePolicy:
    """Per-space knobs. `access_threshold` opens the vault; `governance_threshold` changes
    membership. Both are genuine quorums (Shamir needs k > 1)."""

    access_threshold: int
    governance_threshold: int

    def validate_for(self, n: int) -> None:
        for name, k in (("access", self.access_threshold), ("governance", self.governance_threshold)):
            if not 1 < k <= n:
                raise SpaceError(f"{name}_threshold must satisfy 1 < k <= members ({n})")
        # The root polynomial has degree access_threshold-1, so a reshare that reconstructs it
        # from only `governance_threshold` points would interpolate a WRONG polynomial when
        # governance < access -> a garbage root, silently, and every existing vault item becomes
        # permanently unopenable. Require governance to be at least the access quorum.
        if self.governance_threshold < self.access_threshold:
            raise SpaceError(
                "governance_threshold must be >= access_threshold (a reshare reconstructs the "
                "root, which needs the access quorum; fewer points silently corrupts it)")


@dataclass(frozen=True)
class VaultItem:
    """One ciphertext in the space's store. `aad` binds it to the space; the store learns nothing."""

    space_id: bytes
    ciphertext: bytes


@dataclass
class Space:
    """The self-hosted, shareable space state — CIPHERTEXT + public roster/policy only. Holds no
    root, no share, no plaintext. Members hold their own shares out of band."""

    space_id: bytes
    policy: SpacePolicy
    member_nyms: List[bytes] = field(default_factory=list)
    store: List[VaultItem] = field(default_factory=list)

    def is_member(self, nym: bytes) -> bool:
        return nym in self.member_nyms

    def size(self) -> int:
        return len(self.member_nyms)


def _vault_key(space_root: bytes, space_id: bytes) -> bytes:
    """Tenant-isolated vault key: derived from the space root, namespaced by space_id, so no two
    spaces share a keyspace even with the same members."""
    return hkdf(ikm=space_root, info=_VAULT + b"/" + space_id, length=32)


def _reconstruct(shares: Sequence[shamir.Share], k: int, err: type[SpaceError]) -> bytes:
    if len(shares) < k:
        raise err(f"need {k} shares, got {len(shares)}")
    return shamir.combine(list(shares))


def create_space(space_id: bytes, member_roots: Sequence[bytes],
                 policy: SpacePolicy) -> tuple[Space, Dict[bytes, shamir.Share]]:
    """Found a space over `member_roots`. Each member joins under their space-nym (#13). Returns
    the (secret-free) `Space` plus `{nym: share}` to hand to each member. The space root is fresh
    QRNG and is split k=access_threshold of n=members; it is not retained anywhere."""
    n = len(member_roots)
    policy.validate_for(n)
    nyms = [join_space(r, space_id).nym for r in member_roots]
    if len(set(nyms)) != n:
        raise SpaceError("duplicate members (same root joined twice)")

    space_root = random_bytes(32)
    shares = shamir.split(space_root, n=n, k=policy.access_threshold)
    roster = dict(zip(nyms, shares))
    return Space(space_id=space_id, policy=policy, member_nyms=nyms), roster


def seal_to_vault(space: Space, plaintext: bytes,
                  present_shares: Sequence[shamir.Share]) -> VaultItem:
    """Store `plaintext` in the space vault. Needs ≥ access_threshold present members' shares to
    form the vault key. Only ciphertext is stored."""
    root = _reconstruct(present_shares, space.policy.access_threshold, AccessError)
    ct = aead_encrypt(_vault_key(root, space.space_id), plaintext, aad=space.space_id)
    item = VaultItem(space_id=space.space_id, ciphertext=ct)
    space.store.append(item)
    return item


def open_vault(space: Space, item: VaultItem,
               present_shares: Sequence[shamir.Share]) -> bytes:
    """Open a stored item. Fail-closed below the access threshold, or on a wrong-space item."""
    if item.space_id != space.space_id:
        raise AccessError("item belongs to a different space")
    root = _reconstruct(present_shares, space.policy.access_threshold, AccessError)
    try:
        return aead_decrypt(_vault_key(root, space.space_id), item.ciphertext, aad=space.space_id)
    except Exception as exc:
        raise AccessError("vault open failed (wrong shares)") from exc


def _reshare(space: Space, governance_shares: Sequence[shamir.Share],
             new_member_roots: Sequence[bytes]) -> tuple[Space, Dict[bytes, shamir.Share]]:
    """Governance-gated membership change: reconstruct the SAME root, re-split to the new member
    set (old shares invalidated, root unchanged), re-derive nyms. The vault contents survive."""
    root = _reconstruct(governance_shares, space.policy.governance_threshold, GovernanceError)
    n = len(new_member_roots)
    space.policy.validate_for(n)
    nyms = [join_space(r, space.space_id).nym for r in new_member_roots]
    if len(set(nyms)) != n:
        raise SpaceError("duplicate members after reshare")
    new_shares = shamir.split(root, n=n, k=space.policy.access_threshold)
    updated = Space(space_id=space.space_id, policy=space.policy,
                    member_nyms=nyms, store=space.store)
    return updated, dict(zip(nyms, new_shares))


def add_member(space: Space, new_member_root: bytes, current_member_roots: Sequence[bytes],
               governance_shares: Sequence[shamir.Share]) -> tuple[Space, Dict[bytes, shamir.Share]]:
    """Add a member (governance-gated). Reshares the root to current members + the newcomer."""
    if join_space(new_member_root, space.space_id).nym in space.member_nyms:
        raise SpaceError("already a member")
    return _reshare(space, governance_shares, list(current_member_roots) + [new_member_root])


def remove_member(space: Space, target_root: bytes, remaining_member_roots: Sequence[bytes],
                  governance_shares: Sequence[shamir.Share]) -> tuple[Space, Dict[bytes, shamir.Share]]:
    """Remove a member (governance-gated) with TRUE revocation. A plain reshare preserves the root,
    so the removed member's OLD share still reconstructs it together with any RETAINED old share —
    that is not real revocation. Instead we ROTATE to a fresh root and RE-ENCRYPT the vault under
    it: every old share (removed or retained) now decrypts nothing, because the store is sealed
    under a root no old share can form. (Inherent caveat, as with any crypto revocation: this
    protects the CURRENT store going forward; it cannot un-give ciphertext a member already copied
    before removal.)"""
    target_nym = join_space(target_root, space.space_id).nym
    if target_nym not in space.member_nyms:
        raise SpaceError("not a member")
    remaining_nyms = {join_space(r, space.space_id).nym for r in remaining_member_roots}
    if target_nym in remaining_nyms:
        raise SpaceError("target still present in the remaining set")

    old_root = _reconstruct(governance_shares, space.policy.governance_threshold, GovernanceError)
    n = len(remaining_member_roots)
    space.policy.validate_for(n)
    nyms = [join_space(r, space.space_id).nym for r in remaining_member_roots]
    if len(set(nyms)) != n:
        raise SpaceError("duplicate members after removal")

    new_root = random_bytes(32)
    old_key = _vault_key(old_root, space.space_id)
    new_key = _vault_key(new_root, space.space_id)
    rekeyed_store: List[VaultItem] = []
    for item in space.store:
        plaintext = aead_decrypt(old_key, item.ciphertext, aad=space.space_id)   # governance quorum only
        rekeyed_store.append(VaultItem(space_id=space.space_id,
                                       ciphertext=aead_encrypt(new_key, plaintext, aad=space.space_id)))

    new_shares = shamir.split(new_root, n=n, k=space.policy.access_threshold)
    updated = Space(space_id=space.space_id, policy=space.policy,
                    member_nyms=nyms, store=rekeyed_store)
    return updated, dict(zip(nyms, new_shares))
