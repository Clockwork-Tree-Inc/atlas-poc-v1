"""Real-ID verifier seam: Path A chip-chain verify, Path B labeled vendor, liveness-bind, and the
document nullifier (idempotent + one-document-one-System-ID reuse block). Entitlement stubbed."""

import os

import pytest

from atlas.crypto.sign import generate_sig_keypair
from atlas.keys.identity import PseudonymTier, build_identity_tree
from atlas.realid.levels import AssuranceLevel
from atlas.realid.verification import AtlasVerificationAuthority
from atlas.realid.verifier import (DocPath, DocumentAttestation, RealIDReuse, RealIDVerifier,
                                    document_nullifier, mint_chip_attestation, verify_chip)


def _system_id():
    return build_identity_tree(os.urandom(32)).profile("me", PseudonymTier.PUBLIC).handle


def _verifier():
    csca = generate_sig_keypair()
    return RealIDVerifier(AtlasVerificationAuthority(), csca.public), csca


def test_chip_path_verifies_and_certifies_high_confidence():
    v, csca = _verifier()
    att = mint_chip_attestation(csca, generate_sig_keypair(), b"passport:CAN:AA1234:1990")
    assert verify_chip(att, csca.public)
    sid = _system_id()
    res = v.certify(sid, att, live_present=True)
    assert res.cryptographic is True
    assert res.credential.level == AssuranceLevel.L1        # verified real human; ID not revealed
    assert v._authority.is_unique_root(sid)


def test_bad_chain_rejected():
    v, csca = _verifier()
    # DSC signed by the WRONG csca -> chain break
    att = mint_chip_attestation(generate_sig_keypair(), generate_sig_keypair(), b"passport:CAN:AA1234:1990")
    assert not verify_chip(att, csca.public)
    with pytest.raises(ValueError):
        v.certify(_system_id(), att, live_present=True)


def test_liveness_required():
    v, csca = _verifier()
    att = mint_chip_attestation(csca, generate_sig_keypair(), b"passport:CAN:AA1234:1990")
    with pytest.raises(ValueError):
        v.certify(_system_id(), att, live_present=False)


def test_vendor_path_is_labeled_lower_confidence():
    v, _ = _verifier()
    ok = DocumentAttestation(path=DocPath.VENDOR, doc_unique=b"dl:onfido:xyz", vendor="onfido", vendor_ok=True)
    res = v.certify(_system_id(), ok, live_present=True)
    assert res.cryptographic is False                       # labeled trust-the-vendor
    assert res.credential.level == AssuranceLevel.L1
    bad = DocumentAttestation(path=DocPath.VENDOR, doc_unique=b"dl:onfido:no", vendor="onfido", vendor_ok=False)
    with pytest.raises(ValueError):
        v.certify(_system_id(), bad, live_present=True)


def test_document_nullifier_idempotent_and_reuse_blocked():
    v, csca = _verifier()
    doc = b"passport:CAN:ZZ9999:1985"
    att = mint_chip_attestation(csca, generate_sig_keypair(), doc)
    assert document_nullifier(doc) == document_nullifier(doc)   # idempotent
    sid1 = _system_id()
    v.certify(sid1, att, live_present=True)
    v.certify(sid1, att, live_present=True)                     # same person re-certifies -> fine
    with pytest.raises(RealIDReuse):                            # different System-ID, same document -> blocked
        v.certify(_system_id(), att, live_present=True)
