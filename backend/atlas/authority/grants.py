"""Cross-boundary permissioned grants — the Atlas authority engine (Phase D).

Capability-based authorization: a `Grant` is a SIGNED, delegatable statement rooted at a resource's
controller. Access = a CHAIN of grants back to that root. The chain is **rooted, monotonically
attenuating, signature-chained, revocable, and personhood-gated** — so privilege escalation is
structurally impossible rather than defended against. See `AUTHORITY_MODEL.md`.

NOT new crypto: this is the macaroon / SPKI delegation model, Atlas-native — personas (HybridSig
public keys) as principals, grants as ledgerable events, the personhood gate as the sybil defense.

DECISIONS (AUTHORITY_MODEL §7): (1) rights = a per-resource LADDER level + orthogonal capability
FLAGS; (2) check-time revocation set + short expiries; (3) ROOT-SIGNED rotation certs; (4) freshness
tiered by stakes (accountable rights require a fresh revocation view).

Every check is FAIL-CLOSED: `verify_chain` raises `AuthorityError` on any violation; it never
returns a partial or "probably fine" result.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional, Sequence, Union

from ..crypto.primitives import H
from ..crypto.sign import HybridSigKeypair, HybridSigPublic, keypair_from_seed, sign, verify
from .fs_sign import FSPublicKey, FSSigner, _leaf_hash, _leaf_seed, _root_from_path

# Sentinel parent for a ROOT grant (a grant issued directly by a resource's root authority).
ROOT = b"\x00" * 32

# Capability flag that marks an ACCOUNTABLE right (economics / admin / credential-issuing). Its
# GRANTEE must be a verified unique human (personhood gate, I8).
ACCOUNTABLE = "accountable"

_GRANT_DOMAIN = b"atlas/authority/grant/v1"
_ROTATE_DOMAIN = b"atlas/authority/rotate/v1"


class AuthorityError(Exception):
    """A grant chain failed verification — fail-closed. The message says which invariant broke."""


def _lp(b: bytes) -> bytes:
    """Length-prefix framing so no field can bleed into the next (A11: unambiguous encoding)."""
    return len(b).to_bytes(4, "big") + b


# --------------------------------------------------------------------------- rights
@dataclass(frozen=True)
class RightSet:
    """Rights on a resource: a LADDER `level` (higher = more; meaning is per-resource-type) PLUS an
    orthogonal set of capability `flags`. Attenuation = level may only drop and flags may only shrink."""

    level: int
    flags: frozenset[str] = field(default_factory=frozenset)

    def is_subset_of(self, other: "RightSet") -> bool:
        """True iff these rights are <= `other` on BOTH axes (the attenuation partial order)."""
        return self.level <= other.level and self.flags <= other.flags

    def encode(self) -> bytes:
        flags = b"".join(_lp(f.encode()) for f in sorted(self.flags))
        return self.level.to_bytes(4, "big") + _lp(flags)


@dataclass(frozen=True)
class Caveat:
    """An accumulating constraint. `key="expiry"` value = epoch (checked vs `now`); other keys are
    opaque to the engine (the resource enforces them at use) but still attenuate (accumulate)."""

    key: str
    value: str

    def encode(self) -> bytes:
        return _lp(self.key.encode()) + _lp(self.value.encode())


# --------------------------------------------------------------------------- grant
@dataclass
class Grant:
    """A signed, delegatable capability. `parent` is the grant_id of the parent (or ROOT). `sig` is
    the GRANTOR's signature over the canonical encoding — unforgeable without the grantor's key."""

    grantor: HybridSigPublic
    grantee: HybridSigPublic
    resource: bytes
    rights: RightSet
    caveats: frozenset[Caveat]
    delegable_depth: int      # 0 = leaf (cannot delegate); N = may delegate down to depth N-1
    parent: bytes             # grant_id of the parent, or ROOT
    epoch: int
    sig: bytes = b""
    # FS membership proof — set ONLY on a ROOT grant issued by a forward-secure signer (issue_fs).
    # Proves the SIGNING leaf (grantor) is the FS root's epoch-`fs_epoch` leaf. EXCLUDED from _body()
    # / grant_id (it is a proof, not part of the grant's identity).
    fs_epoch: Optional[int] = None
    fs_auth_path: Optional[Sequence[bytes]] = None

    def _body(self) -> bytes:
        return _assemble_grant_body(self.grantor.encode(), self.grantee.encode(), self.resource,
                                    self.rights, self.caveats, self.delegable_depth, self.parent,
                                    self.epoch)

    def grant_id(self) -> bytes:
        return H(b"atlas/authority/grant-id", self._body())


def _assemble_grant_body(grantor_enc: bytes, grantee_enc: bytes, resource: bytes, rights: "RightSet",
                         caveats, depth: int, parent: bytes, epoch: int) -> bytes:
    """Canonical grant body from RAW encoded components (the parity-critical glue). Kept separate so
    the encoding can be pinned with fixed public-key bytes, independent of keygen. Mirrors the Swift
    `Authority.grantBody(grantorEnc:...)`."""
    cav = b"".join(c.encode() for c in sorted(caveats, key=lambda c: (c.key, c.value)))
    return b"".join([
        _GRANT_DOMAIN, _lp(grantor_enc), _lp(grantee_enc), _lp(resource),
        _lp(rights.encode()), _lp(cav), depth.to_bytes(4, "big"), _lp(parent),
        epoch.to_bytes(8, "big"),
    ])


def grant_id_from_parts(*, grantor_enc: bytes, grantee_enc: bytes, resource: bytes, rights: "RightSet",
                        caveats, depth: int, parent: bytes, epoch: int) -> bytes:
    """grant_id from raw encoded public bytes + fields (parity helper; mirrors Swift Authority.grantId)."""
    return H(b"atlas/authority/grant-id",
             _assemble_grant_body(grantor_enc, grantee_enc, resource, rights, caveats, depth, parent, epoch))


# --------------------------------------------------------------------------- rotation (decision 3)
@dataclass
class RotationCert:
    """A ROOT-SIGNED statement that `new_root` replaces `old_root` as the controller of `resource`.
    Lets grants signed under an old root key still verify after a rotation, without re-issuing them."""

    resource: bytes
    old_root: HybridSigPublic
    new_root: HybridSigPublic
    epoch: int
    sig: bytes = b""

    def _body(self) -> bytes:
        return b"".join([
            _ROTATE_DOMAIN, _lp(self.resource),
            _lp(self.old_root.encode()), _lp(self.new_root.encode()),
            self.epoch.to_bytes(8, "big"),
        ])


_REVOKE_DOMAIN = b"atlas/authority/revoke/v1"


@dataclass
class Revocation:
    """A SIGNED revocation of a grant (by grant_id). Honored ONLY if the revoker is the target's
    grantor or an ANCESTOR grantor in the chain (I7, A15) — an unauthenticated revocation set would
    let a griefer drop a victim's grant_id in and kill their access (revoke-as-DoS)."""

    target: bytes                 # grant_id being revoked
    revoker: HybridSigPublic
    epoch: int
    sig: bytes = b""

    def _body(self) -> bytes:
        return b"".join([_REVOKE_DOMAIN, _lp(self.target),
                         _lp(self.revoker.encode()), self.epoch.to_bytes(8, "big")])


def revoke(target: Grant, revoker_kp: HybridSigKeypair, *, epoch: int = 0) -> Revocation:
    """Produce a signed revocation of `target`. Authorization (revoker is grantor/ancestor) is
    enforced at verify time against the actual chain."""
    r = Revocation(target=target.grant_id(), revoker=revoker_kp.public, epoch=epoch)
    r.sig = sign(revoker_kp, r._body())
    return r


# --------------------------------------------------------------------------- issue / delegate / revoke
def issue(root_kp: HybridSigKeypair, *, grantee: HybridSigPublic, resource: bytes,
          rights: RightSet, caveats: Sequence[Caveat] = (), delegable_depth: int = 0,
          epoch: int = 0) -> Grant:
    """A resource ROOT issues a grant directly (parent = ROOT). The root IS the authority for this
    resource; verification pins the chain's root grantor to the resource's known root key (I1/I12)."""
    g = Grant(grantor=root_kp.public, grantee=grantee, resource=resource, rights=rights,
              caveats=frozenset(caveats), delegable_depth=delegable_depth, parent=ROOT, epoch=epoch)
    g.sig = sign(root_kp, g._body())
    return g


def delegate(parent: Grant, holder_kp: HybridSigKeypair, *, grantee: HybridSigPublic,
             rights: RightSet, add_caveats: Sequence[Caveat] = (), epoch: int = 0) -> Grant:
    """The holder of `parent` (its grantee) delegates a SUBSET onward. Enforced at creation AND
    re-checked at verify: rights ⊆ parent.rights, caveats ⊇ parent.caveats, parent must be delegable
    (depth >= 1), depth decrements, and the signer must be parent.grantee (chain continuity, I5)."""
    if holder_kp.public.encode() != parent.grantee.encode():
        raise AuthorityError("only the parent's grantee may delegate it (I5 continuity)")
    if parent.delegable_depth < 1:
        raise AuthorityError("parent grant is not delegable (I3)")
    if not rights.is_subset_of(parent.rights):
        raise AuthorityError("delegated rights must be a subset of the parent's (I2)")
    caveats = frozenset(parent.caveats) | frozenset(add_caveats)
    g = Grant(grantor=parent.grantee, grantee=grantee, resource=parent.resource, rights=rights,
              caveats=caveats, delegable_depth=parent.delegable_depth - 1,
              parent=parent.grant_id(), epoch=epoch)
    g.sig = sign(holder_kp, g._body())
    return g


def issue_fs(signer: FSSigner, *, grantee: HybridSigPublic, resource: bytes, rights: RightSet,
             caveats: Sequence[Caveat] = (), delegable_depth: int = 0, epoch: int = 0) -> Grant:
    """Issue a ROOT grant from a FORWARD-SECURE signer (the A13 fix). The grant is signed by the FS
    signer's CURRENT-epoch leaf; its `grantor` is that leaf and it carries a Merkle MEMBERSHIP PROOF
    (fs_epoch + fs_auth_path) binding the leaf to the FS public root. Verified against an `FSPublicKey`
    resource_root. A compromised signer can only sign at the current epoch and cannot reconstruct a
    past leaf's secret, so it cannot backdate a root grant. `epoch` is the grant's own (unrelated)
    field; the FS epoch is intrinsic to the leaf."""
    leaf_pub = keypair_from_seed(_leaf_seed(signer._state)).public
    g = Grant(grantor=leaf_pub, grantee=grantee, resource=resource, rights=rights,
              caveats=frozenset(caveats), delegable_depth=delegable_depth, parent=ROOT, epoch=epoch)
    fs_sig = signer.sign(g._body())                       # signs the body at the current FS epoch
    g.sig = fs_sig.sig
    g.fs_epoch = fs_sig.epoch
    g.fs_auth_path = list(fs_sig.auth_path)
    return g


def _expiry_ok(caveats: frozenset[Caveat], now: int) -> bool:
    for c in caveats:
        if c.key == "expiry" and now > int(c.value):
            return False
    return True


def _root_authority(resource: bytes, known_root: HybridSigPublic,
                    rotations: Sequence[RotationCert]) -> dict[bytes, Optional[int]]:
    """Map each root pubkey-encoding that legitimately controls `resource` to the epoch its authority
    ENDS (None = the current root, no cutoff). A rotated-out OLD root is valid ONLY for grants with
    `epoch <= cutoff` — so rotating a COMPROMISED key actually ends its power to issue new grants
    (A13). Planned rotation (old grants keep verifying) and compromise recovery (old key can't sign
    new grants past the cut) are now BOTH delivered by one mechanism."""
    authority: dict[bytes, Optional[int]] = {known_root.encode(): None}
    changed = True
    while changed:                      # transitively include old roots reachable by signed rotations
        changed = False
        for r in rotations:
            if r.resource != resource:
                continue
            if not verify(r.old_root, r._body(), r.sig):
                continue                # forged/invalid rotation cert is ignored
            if r.new_root.encode() in authority and r.old_root.encode() not in authority:
                authority[r.old_root.encode()] = r.epoch   # old key's authority ends at the cut
                changed = True
    return authority


def verify_chain(chain: Sequence[Grant], *, resource: bytes,
                 resource_root: Union[HybridSigPublic, FSPublicKey],
                 now: int,
                 revocations: Sequence[Revocation] = (),
                 understood_caveats: frozenset[str] = frozenset(),
                 is_verified_human: Optional[Callable[[HybridSigPublic], bool]] = None,
                 rotations: Sequence[RotationCert] = ()) -> RightSet:
    """FAIL-CLOSED chain validity check (I1–I8). Returns the leaf's effective RightSet iff every
    invariant holds; raises `AuthorityError` otherwise.

    NOT AN ACCESS GATE ON ITS OWN (A14): grants are public ledger events, so a valid chain is
    bearer-replayable. Use `verify_access` (chain + proof-of-possession) to gate actual access.

    `now` is REQUIRED (a fail-open expiry default would be a footgun). `revocations` are SIGNED
    revocations, honored only if the revoker is the target's grantor/ancestor (A15). Every caveat key
    a grant carries must be in `understood_caveats` (plus the built-in `expiry`) or the grant is
    REJECTED — an unrecognized caveat must fail closed (A16). `rotations` bound an old root's
    authority to its cut epoch (A13)."""
    if not chain:
        raise AuthorityError("empty chain")

    valid_revs = [r for r in revocations if verify(r.revoker, r._body(), r.sig)]
    known_caveats = understood_caveats | {"expiry"}
    prev: Optional[Grant] = None
    for i, g in enumerate(chain):
        # resource binding — every grant must be about THIS resource.
        if g.resource != resource:
            raise AuthorityError(f"grant {i}: resource mismatch")
        # signature — the grantor actually signed this grant (A3 forgery).
        if not verify(g.grantor, g._body(), g.sig):
            raise AuthorityError(f"grant {i}: bad signature")
        # unrecognized caveats fail CLOSED (A16): a verifier must understand every caveat or deny.
        for c in g.caveats:
            if c.key not in known_caveats:
                raise AuthorityError(f"grant {i}: unrecognized caveat '{c.key}' — fail closed (A16)")
        # expiry satisfied now (A7).
        if not _expiry_ok(g.caveats, now):
            raise AuthorityError(f"grant {i}: expired")
        # authenticated revocation (I7, A8, A15): honored only if a signed revocation targets this
        # grant AND its revoker is this grant's grantor or an ancestor grantor (i.e. on the authority
        # line up to here). An unauthorized/forged revocation is ignored — no revoke-as-DoS.
        gid = g.grant_id()
        authority_line = {chain[j].grantor.encode() for j in range(i + 1)}
        if any(r.target == gid and r.revoker.encode() in authority_line for r in valid_revs):
            raise AuthorityError(f"grant {i}: revoked")
        if i == 0:
            if g.parent != ROOT:
                raise AuthorityError("chain[0] is not a root grant")
            if isinstance(resource_root, FSPublicKey):
                # FORWARD-SECURE root (the A13 fix). The signing leaf (`grantor`, already sig-verified
                # above) must be the FS root's epoch-`fs_epoch` leaf, proven by the Merkle membership
                # path. The epoch is INTRINSIC to the leaf's tree position — a compromised current signer
                # can only sign with the current leaf and cannot reconstruct a past leaf's secret, so it
                # cannot backdate a root grant. Backdating dies structurally.
                if g.fs_epoch is None or g.fs_auth_path is None:
                    raise AuthorityError("root grant under an FS root must carry an FS membership proof")
                if not (0 <= g.fs_epoch < (1 << resource_root.height)):
                    raise AuthorityError("FS epoch out of range")
                if len(g.fs_auth_path) != resource_root.height:
                    raise AuthorityError("FS auth path wrong length")
                leaf_hash = _leaf_hash(g.grantor.encode())
                if _root_from_path(leaf_hash, g.fs_epoch, list(g.fs_auth_path)) != resource_root.root:
                    raise AuthorityError("root grant's signing leaf is not in the FS root tree at that epoch (A13)")
            else:
                # Legacy HybridSigPublic root (no forward security). Grantor must be the resource root
                # (I1/I12, A12); a rotated-out root is RETIRED (A13 interim — see RotationCert / §A13).
                authority = _root_authority(resource, resource_root, rotations)
                if g.grantor.encode() not in authority:
                    raise AuthorityError("chain[0] grantor is not the resource root (A12)")
                if authority[g.grantor.encode()] is not None:
                    raise AuthorityError("chain[0] root is rotated out / retired — re-issue under the new root (A13 open)")
        else:
            assert prev is not None
            # continuity — parent hash + parent.grantee == this.grantor (I5, A6 splicing).
            if g.parent != prev.grant_id():
                raise AuthorityError(f"grant {i}: parent hash mismatch (A6)")
            if g.grantor.encode() != prev.grantee.encode():
                raise AuthorityError(f"grant {i}: grantor is not the parent's grantee (I5)")
            # delegation allowed and depth strictly decreasing (I3, A4).
            if prev.delegable_depth < 1:
                raise AuthorityError(f"grant {i}: parent not delegable (A4)")
            if g.delegable_depth != prev.delegable_depth - 1:
                raise AuthorityError(f"grant {i}: delegation depth must decrement by one (A4)")
            # monotonic attenuation — rights only narrow, caveats only accumulate (I2, A1/A10).
            if not g.rights.is_subset_of(prev.rights):
                raise AuthorityError(f"grant {i}: rights escalate beyond parent (A1)")
            if not prev.caveats <= g.caveats:
                raise AuthorityError(f"grant {i}: caveats were dropped (A10)")
        # personhood gate — accountable rights require a verified human grantee (I8, A9).
        if ACCOUNTABLE in g.rights.flags:
            if is_verified_human is None or not is_verified_human(g.grantee):
                raise AuthorityError(f"grant {i}: accountable right to an unverified grantee (A9)")
        prev = g
    assert prev is not None
    return prev.rights


def verify_access(chain: Sequence[Grant], *, challenge: bytes, proof: bytes, now: int,
                  resource: bytes, resource_root: HybridSigPublic, **kw) -> RightSet:
    """The ACCESS GATE (A14): verify the chain AND require the presenter to PROVE POSSESSION of the
    leaf grantee's key by signing a fresh `challenge`. `verify_chain` alone is not sufficient —
    grants live on a public ledger, so a chain is bearer-replayable by anyone who reads it. Callers
    gating real access MUST use this, with a fresh single-use `challenge`. (Hardening: bind the
    context — resource + leaf grant_id — INTO the challenge so a PoP can't be cross-used across
    concurrent accesses; fresh single-use challenges already cover the basic case.)"""
    rights = verify_chain(chain, resource=resource, resource_root=resource_root, now=now, **kw)
    leaf = chain[-1]
    if not verify(leaf.grantee, challenge, proof):
        raise AuthorityError("proof-of-possession failed: presenter does not hold the grantee key (A14)")
    return rights
