"""Interop hub + W3C VC adapter (§ interop)."""

import base64
import json

from atlas.crypto.sign import keypair_from_seed
from atlas.interop.assertion import (
    CLAIM_LIVE_HUMAN,
    AtlasAssertion,
    b64u_dec,
    issue,
    kid_of,
    verify,
)
from atlas.interop.vc import to_jws, verify_jws
from atlas.interop.oidc import id_token, verify_id_token
from atlas.interop.did import did_for, did_document, jwks, resolve


def _kp():
    return keypair_from_seed(b"interop-test-seed-32-bytes-long!!")


def _assertion(pub):
    return AtlasAssertion(
        subject="did:atlas:user-nym-abc",
        claim_type=CLAIM_LIVE_HUMAN,
        claims={"tier": "ambient", "verified": True, "gate": "presence"},
        issued_at=1000.0,
        epoch="deadbeef",
        issuer_kid=kid_of(pub),
    )


def test_assertion_roundtrip_and_tamper():
    kp = _kp()
    signed = issue(kp, _assertion(kp.public))
    assert verify(kp.public, signed) is True
    signed.assertion.claims["verified"] = False      # tamper a verdict
    assert verify(kp.public, signed) is False


def test_assertion_wrong_key_rejected():
    kp = _kp()
    other = keypair_from_seed(b"another-seed-32-bytes-long-xxxxxx")
    signed = issue(kp, _assertion(kp.public))
    assert verify(other.public, signed) is False


def test_vc_jws_is_standard_shape():
    kp = _kp()
    jws = to_jws(kp, _assertion(kp.public))
    parts = jws.split(".")
    assert len(parts) == 3
    header = json.loads(b64u_dec(parts[0]))
    assert header["alg"] == "EdDSA" and header["typ"] == "vc+jwt"
    payload = json.loads(b64u_dec(parts[1]))
    assert payload["iss"].startswith("did:atlas:")
    assert "VerifiableCredential" in payload["vc"]["type"]


def test_vc_verify_roundtrip_pqc_and_eddsa_only():
    kp = _kp()
    jws = to_jws(kp, _assertion(kp.public))
    payload = verify_jws(kp.public, jws)                       # EdDSA + embedded ML-DSA
    assert payload is not None
    assert payload["vc"]["credentialSubject"]["claim_type"] == CLAIM_LIVE_HUMAN
    # the EdDSA-only path (what a stock JOSE verifier does) must also accept it
    assert verify_jws(kp.public, jws, require_pqc=False) is not None


def test_vc_tamper_and_wrong_key_rejected():
    kp = _kp()
    other = keypair_from_seed(b"another-seed-32-bytes-long-xxxxxx")
    jws = to_jws(kp, _assertion(kp.public))
    h, _p, s = jws.split(".")
    bad_payload = base64.urlsafe_b64encode(b'{"iss":"evil"}').rstrip(b"=").decode()
    assert verify_jws(kp.public, h + "." + bad_payload + "." + s) is None   # tampered payload
    assert verify_jws(other.public, jws) is None                             # wrong issuer key


def test_oidc_id_token_roundtrip_and_audience():
    kp = _kp()
    tok = id_token(kp, subject="did:atlas:user-nym-abc", audience="https://rp.example",
                   nonce="n-123", epoch="deadbeef", issued_at=1000.0, expires_at=1300.0)
    p = verify_id_token(kp.public, tok, audience="https://rp.example")
    assert p is not None and p["atlas_verified_human"] is True and p["nonce"] == "n-123"
    assert verify_id_token(kp.public, tok, audience="https://evil.example") is None   # aud mismatch
    assert verify_id_token(kp.public, tok, require_pqc=False) is not None             # stock OIDC path


def test_oidc_wrong_key_rejected():
    kp = _kp()
    other = keypair_from_seed(b"another-seed-32-bytes-long-xxxxxx")
    tok = id_token(kp, subject="s", audience="a", nonce="n", epoch="e", issued_at=1.0, expires_at=2.0)
    assert verify_id_token(other.public, tok) is None


def test_did_document_resolve_roundtrip():
    kp = _kp()
    doc = did_document(kp.public)
    assert doc["id"] == did_for(kp.public)
    resolved = resolve(doc)
    assert resolved is not None
    assert resolved.ed_pk == kp.public.ed_pk and resolved.mldsa_pk == kp.public.mldsa_pk


def test_verify_credential_via_resolved_did_only():
    # A verifier holding ONLY the DID document (not the keypair) can verify both envelopes.
    kp = _kp()
    doc = did_document(kp.public)
    resolved = resolve(doc)                                   # what an external verifier does
    assert verify_jws(resolved, to_jws(kp, _assertion(kp.public))) is not None
    tok = id_token(kp, subject="s", audience="a", nonce="n", epoch="e", issued_at=1.0, expires_at=2.0)
    assert verify_id_token(resolved, tok, audience="a") is not None


def test_jwks_has_standard_ed25519_key():
    kp = _kp()
    k = jwks(kp.public)["keys"][0]
    assert k["kty"] == "OKP" and k["crv"] == "Ed25519" and k["alg"] == "EdDSA"
    assert b64u_dec(k["x"]) == kp.public.ed_pk
