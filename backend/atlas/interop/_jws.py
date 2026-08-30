"""Shared compact-JWS (JOSE) machinery for the Atlas interop adapters.

Every Atlas standard envelope (VC, OIDC ID token, …) is an EdDSA-signed compact
JWS:  b64u(header) . b64u(payload) . b64u(EdDSA-sig-over-"header.payload").

The payload carries an embedded post-quantum binding under the `atlas` claim:
    payload["atlas"]["assertion_b64"] = b64u(canonical Atlas assertion bytes)
    payload["atlas"]["pqc_mldsa"]     = b64u(ML-DSA-65 signature over those bytes)

The EdDSA envelope (alg=EdDSA, a REGISTERED JOSE algorithm) is what any stock JOSE
verifier checks — that is what makes it interop. The ML-DSA-65 binding is the
Atlas-native post-quantum layer, verified additionally by Atlas-aware verifiers.
The hybrid combo is not a registered JOSE alg, so it rides alongside rather than
as the envelope signature.
"""
from __future__ import annotations

import json
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from dilithium_py.ml_dsa import ML_DSA_65

from ..crypto.sign import HybridSigKeypair, HybridSigPublic
from .assertion import b64u, b64u_dec


def seg(obj: dict) -> str:
    """One compact-JWS segment: b64url of canonical (sorted-key, tight) JSON."""
    return b64u(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode())


def pqc_binding(kp: HybridSigKeypair, canonical: bytes) -> dict[str, str]:
    """The embedded post-quantum block: the canonical assertion + ML-DSA over it.
    Spread into the payload's `atlas` claim by each adapter."""
    return {
        "assertion_b64": b64u(canonical),
        "pqc_mldsa": b64u(ML_DSA_65.sign(kp.mldsa_sk, canonical)),
    }


def sign_compact(kp: HybridSigKeypair, header: dict, payload: dict) -> str:
    """Build an EdDSA-signed compact JWS from header + payload dicts."""
    signing_input = seg(header) + "." + seg(payload)
    return signing_input + "." + b64u(kp.ed_sk.sign(signing_input.encode()))


def verify_compact(pub: HybridSigPublic, jws: str, *, require_pqc: bool = True) -> Optional[dict]:
    """Verify the EdDSA envelope (identical to what any JOSE lib does) and, when
    require_pqc, the embedded ML-DSA binding under payload['atlas']. Returns the
    decoded payload, or None if anything fails to verify or parse."""
    try:
        h_b64, p_b64, s_b64 = jws.split(".")
    except ValueError:
        return None
    signing_input = (h_b64 + "." + p_b64).encode()
    try:
        Ed25519PublicKey.from_public_bytes(pub.ed_pk).verify(b64u_dec(s_b64), signing_input)
    except (InvalidSignature, ValueError):
        return None
    try:
        payload: dict[str, Any] = json.loads(b64u_dec(p_b64))
    except Exception:
        return None
    if require_pqc:
        atlas = payload.get("atlas") or {}
        try:
            canonical = b64u_dec(atlas["assertion_b64"])
            pqc = b64u_dec(atlas["pqc_mldsa"])
        except Exception:
            return None
        if not ML_DSA_65.verify(pub.mldsa_pk, canonical, pqc):
            return None
    return payload
