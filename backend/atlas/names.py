"""Human-readable NAMES -> persona handles: the discovery / naming-registry layer.

A persona MAY publish a human-readable name (its "domain") so others can find it — opt-in,
per-persona. The name maps to the persona's opaque public handle (the address of its
vault/space). Names are UNIQUE (the first valid claim holds it), and a claim is SIGNED by the
persona's own key, so only the controller of a handle can claim a name for it (you cannot name
someone else's handle). Owners may RELEASE a name; governance may REVOKE it (impersonation).
A persona that publishes NO name stays undiscoverable — discoverability is a deliberate choice,
layered ON TOP of the blind base (nothing here weakens per-persona unlinkability: only the names
a persona chooses to publish become linkable to that persona's handle, and to nothing else).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

from .crypto.primitives import H
from .crypto.sign import HybridSigPublic, sign, verify
from .keys.identity import Child, handle_of


def _claim_body(name: str, handle: bytes, epoch: int) -> bytes:
    return H(b"atlas/name/claim", name.encode(), handle, str(epoch).encode())


@dataclass
class NameClaim:
    name: str
    handle: bytes                 # the persona handle this name resolves to (address of its space)
    public: HybridSigPublic       # the claiming persona's public key
    epoch: int
    sig: bytes = b""


def claim_name(identity: Child, name: str, epoch: int = 0) -> NameClaim:
    """A persona claims a human-readable name for ITS OWN handle, signed by its key."""
    handle = identity.handle
    claim = NameClaim(name=name, handle=handle, public=identity.public, epoch=epoch)
    claim.sig = sign(identity.keypair, _claim_body(name, handle, epoch))
    return claim


def verify_claim(claim: NameClaim) -> bool:
    """Valid iff the claim's handle really IS the handle of its public key AND the signature is
    by that key over (name, handle, epoch). So a claimant must CONTROL the handle it names —
    you cannot register a name that points at a handle you don't hold the key for."""
    if handle_of(claim.public.encode()) != claim.handle:
        return False
    return verify(claim.public, _claim_body(claim.name, claim.handle, claim.epoch), claim.sig)


class NameRegistry:
    """First-valid-claim-holds-it. A name maps to exactly one handle; re-claiming a held name
    with a DIFFERENT handle is rejected (no squatting-over). The SAME handle may refresh its own
    claim (e.g. a new epoch). Release frees a name; revoke frees AND blocks it (governance)."""

    def __init__(self) -> None:
        self._names: Dict[str, NameClaim] = {}
        self._revoked = set()

    def register(self, claim: NameClaim) -> None:
        if not verify_claim(claim):
            raise ValueError("invalid name claim")
        if claim.name in self._revoked:
            raise ValueError("name revoked")
        held = self._names.get(claim.name)
        if held is not None and held.handle != claim.handle:
            raise ValueError("name already taken")
        self._names[claim.name] = claim

    def resolve(self, name: str) -> Optional[bytes]:
        """Human-readable name -> the persona's opaque handle (the address of its space)."""
        c = self._names.get(name)
        return c.handle if c is not None else None

    def release(self, identity: Child, name: str) -> None:
        """The owner (the handle that holds the name) releases it, freeing it for others."""
        held = self._names.get(name)
        if held is not None and held.handle == identity.handle:
            del self._names[name]

    def revoke(self, name: str) -> None:
        """Governance revocation (e.g. verified impersonation) — frees AND blocks the name."""
        self._names.pop(name, None)
        self._revoked.add(name)
