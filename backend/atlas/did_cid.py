"""did:cid exposer — present an Atlas identity as a self-certifying, content-addressed DID so it
resolves in the broader ecosystem (DIF Universal Resolver) without us running a server or a ledger.

A `did:cid` is derived from the HASH of its own verification material: the identifier *is* the
content, so anyone can verify a DID matches its keys by recomputing the hash — no lookup, no trust in
a host. This is exactly how Atlas identities already work (System-ID, persona handles, space nyms are
hash-derived), so this is an INTEROP SKIN over what we have — method/network/mark stay ours; only the
identifier format becomes portable.

Format: `did:cid:f<hex>` where the suffix is multibase base16 (`f`) of H(canonical verification set).
Reference of record. Swift parity: ios/AtlasCore/Sources/AtlasCore/Identity/DidCid.swift.
"""
from __future__ import annotations

from typing import Sequence

from .crypto.primitives import H
from .crypto.sign import HybridSigPublic

_DID_CID = b"atlas/did-cid/v1"
_PREFIX = "did:cid:f"      # 'f' = multibase base16 (lowercase hex)


def _lp(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


def canonical_document(keys: Sequence[HybridSigPublic]) -> bytes:
    """The canonical verification material the DID is addressed to — the SORTED, length-prefixed set
    of public keys (order-independent, framed so adjacent keys can't collide)."""
    encs = sorted(k.encode() for k in keys)
    parts = [_DID_CID, len(encs).to_bytes(4, "big")]
    parts.extend(_lp(e) for e in encs)
    return b"".join(parts)


def did_cid(keys: Sequence[HybridSigPublic]) -> str:
    """The content-addressed DID for this verification set. Same keys -> same DID, anywhere."""
    return _PREFIX + H(canonical_document(keys)).hex()


def did_for(public: HybridSigPublic) -> str:
    """Convenience: the did:cid for a single-key identity (a persona / org / space)."""
    return did_cid([public])


def verify_did(did: str, keys: Sequence[HybridSigPublic]) -> bool:
    """Self-certifying check: the DID must equal the hash of its own verification set. No resolver,
    no host, no ledger — the identifier proves its own binding to the keys."""
    return did == did_cid(keys)
