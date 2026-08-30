"""C2PA content-credential adapter (§ interop).

Skips cleanly when c2pa-python (or Pillow) isn't installed — the C2PA adapter is
an OPTIONAL dependency and must never break the core CI import surface. When the
deps ARE present, this proves the full loop: embed the Atlas VC into a real image
as a signed C2PA manifest, then read it back and confirm it validates with zero
failures and the VC round-trips byte-identical.
"""

import pytest

pytest.importorskip("c2pa", reason="c2pa-python not installed (optional interop dep)")
pytest.importorskip("PIL", reason="Pillow not installed (needed to synthesize a test image)")

from atlas.crypto.sign import keypair_from_seed
from atlas.interop.assertion import CLAIM_PROOF_OF_EXPERIENCE, AtlasAssertion, kid_of
from atlas.interop.vc import to_jws, verify_jws
from atlas.interop.did import did_for
from atlas.interop.c2pa import embed_assertion, make_test_signer, read_assertion


def _kp():
    return keypair_from_seed(b"c2pa-interop-test-seed-32-bytes!!")


def _vc_jws(kp):
    a = AtlasAssertion(
        subject="did:atlas:capturer-nym-001",
        claim_type=CLAIM_PROOF_OF_EXPERIENCE,
        claims={"verdict": "verified-live-human-capture", "tier": "ambient"},
        issued_at=1000.0,
        epoch="deadbeef",
        issuer_kid=kid_of(kp.public),
    )
    return to_jws(kp, a)


def test_c2pa_embed_read_roundtrip_validates(tmp_path):
    kp = _kp()
    vc_jws = _vc_jws(kp)
    issuer_did = did_for(kp.public)

    from PIL import Image

    src = tmp_path / "demo.png"
    Image.new("RGB", (160, 120), (32, 96, 160)).save(src)
    dst = tmp_path / "demo_signed.png"

    cert_chain, key_pem, ca_pem = make_test_signer()
    embed_assertion(
        str(src), str(dst),
        vc_jws=vc_jws, issuer_did=issuer_did, verdict="verified-live-human-capture",
        cert_chain_pem=cert_chain, key_pem=key_pem, fmt="image/png",
    )

    out = read_assertion(str(dst), ca_pem=ca_pem)

    # the correct cert profile (critical EKU) => claim signature validates, no failures
    assert out["failure"] == []
    assert out["validation_state"] in ("Valid", "Trusted")
    assert "claimSignature.validated" in out["success"] or "claimSignature.insideValidity" in out["success"]
    assert "assertion.dataHash.match" in out["success"]

    # the Atlas VC round-trips byte-identical inside the image, and still verifies
    assert out["atlas"] is not None
    assert out["atlas"]["issuer_did"] == issuer_did
    assert out["atlas"]["atlas_vc_jws"] == vc_jws
    assert verify_jws(kp.public, out["atlas"]["atlas_vc_jws"], require_pqc=True) is not None
