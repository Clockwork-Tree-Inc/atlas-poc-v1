"""Atlas interop — wrap the canonical Atlas assertion in existing standards.

The hub is `assertion.AtlasAssertion` (+ issue/verify). Adapters emit it in the
formats the rest of the world already verifies:

  * vc.py           — W3C Verifiable Credential (compact JWS / SD-JWT-style)
  * did.py          — did:atlas DID document + JWKS (Atlas as its own resolvable root)
  * oidc.py         — 'Sign in with Atlas' OIDC ID token
  * c2pa.py         — C2PA content-credential assertion (optional dep: c2pa-python)
  * webauthn_oidc.py — WebAuthn attestation  [planned]

Trust direction: Atlas is its OWN root. The standard envelope is signed with a
REGISTERED algorithm (Ed25519 = JOSE 'EdDSA') so stock external verifiers accept
it; the PQC-hybrid strength (ML-DSA-65) rides as an embedded Atlas-native binding.
Verifiers chain to the Atlas issuer key (did:atlas / a published JWKS), never to
an external trust list.
"""
