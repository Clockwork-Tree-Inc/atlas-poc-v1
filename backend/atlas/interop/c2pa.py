"""C2PA content-credential adapter — embed an Atlas assertion into a media file
as a real C2PA manifest that official C2PA tools (c2pa-python, c2patool, Adobe)
validate.

The Atlas verdict + the full Verifiable Credential ride as a custom C2PA
assertion `com.atlas.proof-of-experience` inside the manifest. Content integrity
(the C2PA hard binding) plus the Atlas assertion travel together in the asset, so
a viewer both verifies the pixels are intact AND sees the proof-of-experience.

Trust direction is unchanged: the Atlas guarantee lives in the embedded VC, which
chains to the Atlas issuer key (did:atlas). The C2PA signing certificate is a
separate transport-layer credential for the content-credential itself.

──────────────────────────────────────────────────────────────────────────────
LOAD-BEARING LESSON (do not regress): the C2PA *certificate profile* is strict.
The end-entity signing certificate MUST have:
  * extendedKeyUsage marked **critical=True**  ← the one that bites
  * keyUsage = digitalSignature (+ contentCommitment), critical
  * basicConstraints CA=False, critical
c2pa-rs >= 0.86 rejects a NON-critical EKU and reports it, misleadingly, as
`claimSignature.mismatch` (NOT a cert error). If you ever see claimSignature.
mismatch while dataHash.match / hashedURI.match pass, suspect the CERT PROFILE
(EKU criticality, KeyUsage bits) — not the signature or the library.
──────────────────────────────────────────────────────────────────────────────

Optional dependency: this module imports `c2pa` (c2pa-python) lazily, so the
package and CI import surface never depend on it. Install with:
    pip install c2pa-python        # needs Python >= 3.10
"""
from __future__ import annotations

import json
import os
from typing import Any, Optional

ATLAS_C2PA_ASSERTION_LABEL = "com.atlas.proof-of-experience"


def _require_c2pa():
    try:
        import c2pa  # noqa: WPS433 (optional dependency, imported lazily)
    except ImportError as exc:  # pragma: no cover - environment-dependent
        raise RuntimeError(
            "c2pa-python is required for the C2PA adapter. "
            "Install it into a Python>=3.10 environment: pip install c2pa-python"
        ) from exc
    return c2pa


def make_test_signer(*, common_name: str = "Atlas Test Signer"):
    """Generate an ES256 (test) signing chain that satisfies the C2PA certificate
    profile. Returns (cert_chain_pem: bytes, key_pem: bytes, ca_pem: bytes).

    For a PoC / reference signer only. Production signers use a real CA-issued
    certificate — but the SAME profile constraints apply (critical EKU!).
    """
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Atlas Test Root CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Atlas Test Root CA"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2024, 1, 1))
        .not_valid_after(datetime.datetime(2034, 1, 1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    ee_key = ec.generate_private_key(ec.SECP256R1())
    ee_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Atlas Test Signing Cert"),
    ])
    ee_cert = (
        x509.CertificateBuilder()
        .subject_name(ee_name).issuer_name(ca_name)
        .public_key(ee_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2024, 1, 1))
        .not_valid_after(datetime.datetime(2031, 1, 1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        # digitalSignature + contentCommitment, critical:
        .add_extension(
            x509.KeyUsage(True, True, False, False, False, False, False, False, False),
            critical=True,
        )
        # EKU MUST be critical for the C2PA profile (see module docstring):
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ee_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    cert_chain = ee_cert.public_bytes(serialization.Encoding.PEM) + ca_cert.public_bytes(serialization.Encoding.PEM)
    key_pem = ee_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    return cert_chain, key_pem, ca_pem


def _es256_callback(key_pem: bytes):
    """Return a callback that signs with ES256 producing a raw r||s (P1363, 64-byte)
    signature — the form COSE/C2PA wants, not DER."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    key = serialization.load_pem_private_key(key_pem, password=None)

    def _sign(data: bytes) -> bytes:
        der = key.sign(data, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    return _sign


def embed_assertion(
    src_path: str,
    dst_path: str,
    *,
    vc_jws: str,
    issuer_did: str,
    verdict: str,
    cert_chain_pem: bytes,
    key_pem: bytes,
    fmt: str = "image/png",
    title: str = "Atlas verified-live-human capture",
) -> str:
    """Embed the Atlas VC + verdict into `src_path` as a signed C2PA manifest and
    write the result to `dst_path`. Returns dst_path.

    The signing certificate MUST follow the C2PA profile — use make_test_signer()
    or a real cert with a CRITICAL extendedKeyUsage.
    """
    c2pa = _require_c2pa()

    manifest = {
        "claim_generator": "atlas_poc/0.1",
        "title": title,
        "assertions": [
            {
                "label": "c2pa.actions",
                "data": {"actions": [{
                    "action": "c2pa.created",
                    "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture",
                }]},
            },
            {
                "label": ATLAS_C2PA_ASSERTION_LABEL,
                "data": {
                    "verdict": verdict,
                    "issuer_did": issuer_did,
                    "atlas_vc_jws": vc_jws,
                },
            },
        ],
    }
    signer = c2pa.Signer.from_callback(
        _es256_callback(key_pem), c2pa.C2paSigningAlg.ES256, cert_chain_pem.decode(), None
    )
    builder = c2pa.Builder(json.dumps(manifest))
    if os.path.exists(dst_path):
        os.remove(dst_path)
    with open(src_path, "rb") as sf, open(dst_path, "wb") as df:
        builder.sign(signer, fmt, sf, df)
    return dst_path


def embed_presence(src_path: str, dst_path: str, kp, att, *, subject: str,
                   cert_chain_pem: bytes, key_pem: bytes, fmt: str = "image/png",
                   title: str = "Atlas verified-live-human asset") -> str:
    """Bake a PRESENCE attestation into `src_path` as a signed C2PA manifest — image OR PDF via `fmt`
    (e.g. "application/pdf") — carrying the verified-live-human VC. Composes presence_interop (which
    produces the VC + verdict + issuer DID) with embed_assertion. So a content asset proves it was
    made by a verified live human at the stated tier, readable by any C2PA verifier."""
    from .presence_interop import as_c2pa_payload
    p = as_c2pa_payload(kp, att, subject=subject)
    return embed_assertion(src_path, dst_path, vc_jws=p["vc_jws"], issuer_did=p["issuer_did"],
                           verdict=p["verdict"], cert_chain_pem=cert_chain_pem, key_pem=key_pem,
                           fmt=fmt, title=title)


def read_assertion(signed_path: str, *, ca_pem: Optional[bytes] = None) -> dict[str, Any]:
    """Read + validate a signed asset. Returns
    {validation_state, success, failure, atlas: {verdict, issuer_did, atlas_vc_jws} | None}.
    If ca_pem is given it is loaded as a trust anchor so signingCredential.trusted
    can be asserted (otherwise the signer reads as 'untrusted', which is expected).
    """
    c2pa = _require_c2pa()
    if ca_pem is not None:
        c2pa.load_settings(json.dumps({
            "trust": {"trust_anchors": ca_pem.decode()},
            "verify": {"verify_trust": True},
        }))
    reader = c2pa.Reader(signed_path)
    report = json.loads(reader.json())
    active = report.get("active_manifest")
    am = report.get("manifests", {}).get(active, {})
    atlas = next(
        (a.get("data") for a in am.get("assertions", []) if a.get("label") == ATLAS_C2PA_ASSERTION_LABEL),
        None,
    )
    results = reader.get_validation_results()
    results = json.loads(results) if isinstance(results, str) else (results or {})
    amv = results.get("activeManifest", {})
    return {
        "validation_state": reader.get_validation_state(),
        "success": sorted({s.get("code") for s in amv.get("success", [])}),
        "failure": [s.get("code") for s in amv.get("failure", [])],
        "atlas": atlas,
    }
