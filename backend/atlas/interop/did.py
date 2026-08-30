"""did:atlas — the issuer identifier the VC/OIDC adapters reference.

Closes the loop for external verifiers: a credential says `iss: did:atlas:<kid>`;
resolving that DID yields a W3C DID document whose verificationMethod is the
Atlas Ed25519 key (as a standard JWK, so any JOSE verifier can use it), plus the
ML-DSA-65 key as an extra method for post-quantum-aware verifiers. A JWKS view is
also provided for plain OIDC/JOSE clients.

Atlas is its own root: the DID document IS the trust anchor. (Production would
publish it at a well-known location / anchor its hash on the transparency log;
here we produce/resolve it as a value.)
"""
from __future__ import annotations

import json
from typing import Optional

from ..crypto.sign import HybridSigPublic
from .assertion import b64u, b64u_dec, kid_of


def did_for(pub: HybridSigPublic) -> str:
    return "did:atlas:" + kid_of(pub)


def did_document(pub: HybridSigPublic) -> dict:
    """W3C DID document for the Atlas issuer key."""
    did = did_for(pub)
    ed_vm = did + "#ed25519"
    mldsa_vm = did + "#mldsa65"
    return {
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": ed_vm,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": b64u(pub.ed_pk), "alg": "EdDSA"},
            },
            {
                # Non-standard PQC method — Atlas-aware verifiers use this for the
                # embedded ML-DSA binding. External JOSE verifiers ignore it.
                "id": mldsa_vm,
                "type": "AtlasMLDSA65Key2026",
                "controller": did,
                "publicKeyBase64url": b64u(pub.mldsa_pk),
            },
        ],
        "assertionMethod": [ed_vm],
        "authentication": [ed_vm],
    }


def jwks(pub: HybridSigPublic) -> dict:
    """Plain JWKS view for stock OIDC/JOSE clients (Ed25519 only — the standard bit)."""
    return {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": b64u(pub.ed_pk),
                "use": "sig",
                "alg": "EdDSA",
                "kid": kid_of(pub) + "#ed25519",
            }
        ]
    }


def resolve(did_document: dict) -> Optional[HybridSigPublic]:
    """Reconstruct the Atlas public key from a DID document (inverse of did_document)."""
    ed_pk: Optional[bytes] = None
    mldsa_pk: Optional[bytes] = None
    for vm in did_document.get("verificationMethod", []):
        jwk = vm.get("publicKeyJwk")
        if jwk and jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
            try:
                ed_pk = b64u_dec(jwk["x"])
            except Exception:
                return None
        elif vm.get("type") == "AtlasMLDSA65Key2026":
            try:
                mldsa_pk = b64u_dec(vm["publicKeyBase64url"])
            except Exception:
                return None
    if ed_pk is None or mldsa_pk is None:
        return None
    return HybridSigPublic(mldsa_pk=mldsa_pk, ed_pk=ed_pk)
