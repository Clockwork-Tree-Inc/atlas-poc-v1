"""Real-ID VERIFIER SEAM — the document front-end to the verification authority.

Two paths feed the existing `AtlasVerificationAuthority`:
  * Path A (PRIMARY, cryptographic): a chip-signed government document (ePassport / ICAO 9303
    Passive Auth, or mDL / ISO 18013-5) whose signature chains to the issuing country
    (SOD -> Document Signer cert -> country CSCA). We VERIFY THAT CHAIN ourselves — the issuing
    government's OWN signature (verification, not authority). On device this is CoreNFC + the ICAO
    PKD; here it is MODELLED with a stub CA. The real chip read needs a PAID Apple entitlement —
    stubbed (`ENTITLEMENT_STUBBED`), same gate as App Attest.
  * Path B (FALLBACK, labeled): a third-party IDV vendor verdict (Onfido/Jumio/…). Trust-the-
    vendor -> explicitly LABELED lower confidence.

Both paths certify at AssuranceLevel L1 (a verified real human; the identity itself is NOT
revealed) — the chip-vs-vendor difference is a separate `cryptographic` confidence flag, not an
exposure level.

LIVENESS-BIND: certification requires a live human present NOW — proving THIS live person holds
THIS genuine document (which a bare vendor "a valid doc exists" cannot).

PROOFS-NOT-DATA: only a DOCUMENT nullifier (document -> exactly one System-ID, so a document can't
be resold onto another) and the person-uniqueness the authority already tracks are kept. Raw
document fields / PII are NEVER retained. One Real-ID per person lives at the System-ID.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional

from ..crypto.primitives import H
from ..crypto.sign import HybridSigPublic, sign, verify
from .levels import AssuranceLevel
from .verification import AtlasVerificationAuthority, VerificationCredential, VerificationRecord

# NFC chip read (ISO 7816) / App Attest need a PAID Apple Developer account ($99/yr). Stubbed here;
# the seam is real, the on-device chip read turns on when the entitlement is present.
ENTITLEMENT_STUBBED = True


class DocPath(Enum):
    CHIP = "chip"       # Path A: cryptographic issuing-country chain (ePassport / mDL)
    VENDOR = "vendor"   # Path B: labeled trust-the-vendor IDV


def document_nullifier(doc_unique: bytes) -> bytes:
    """Deterministic per document: the SAME document (from any source) -> the SAME nullifier
    (idempotent), so a document binds to exactly one System-ID and cannot be resold onto another.
    Only the nullifier is stored — never the document fields / PII."""
    return H(b"atlas/realid/doc-nullifier", doc_unique)


def _sod(doc_unique: bytes) -> bytes:
    return H(b"atlas/realid/sod", doc_unique)


@dataclass
class DocumentAttestation:
    path: DocPath
    doc_unique: bytes                             # unique doc fields (passport no || issuer || DoB) — hashed for the nullifier
    # Path A (chip): the SOD signed by the Document Signer cert; the DSC signed by the country CSCA
    dsc_public: Optional[HybridSigPublic] = None
    sod_sig: bytes = b""
    dsc_sig: bytes = b""
    # Path B (vendor)
    vendor: str = ""
    vendor_ok: bool = False


def mint_chip_attestation(csca_kp, dsc_kp, doc_unique: bytes) -> DocumentAttestation:
    """Model a country issuing a chip-signed document: the CSCA signs the DSC public key; the DSC
    signs the SOD over the document. (On device this is the real ePassport chip + ICAO PKD.)"""
    dsc_sig = sign(csca_kp, dsc_kp.public.encode())
    sod_sig = sign(dsc_kp, _sod(doc_unique))
    return DocumentAttestation(path=DocPath.CHIP, doc_unique=doc_unique,
                               dsc_public=dsc_kp.public, sod_sig=sod_sig, dsc_sig=dsc_sig)


def verify_chip(att: DocumentAttestation, csca_pub: HybridSigPublic) -> bool:
    """Passive-Auth-style chain check: the DSC is signed by the trusted country CSCA, and the SOD
    is signed by that DSC. Any break -> False."""
    if att.path is not DocPath.CHIP or att.dsc_public is None:
        return False
    if not verify(csca_pub, att.dsc_public.encode(), att.dsc_sig):
        return False
    return verify(att.dsc_public, _sod(att.doc_unique), att.sod_sig)


@dataclass
class RealIDResult:
    record: VerificationRecord
    credential: VerificationCredential
    cryptographic: bool          # True = Path A chain-verified (high confidence); False = Path B vendor (labeled)
    doc_nullifier: bytes


class RealIDReuse(Exception):
    """A document already bound to a DIFFERENT System-ID was presented — reuse/resale blocked."""


class RealIDVerifier:
    """The document front-end to the verification authority. Certifies ONE persona's System-ID as
    a verified real human, binding the live person to a genuine document, keeping only nullifiers."""

    def __init__(self, authority: AtlasVerificationAuthority, csca_pub: HybridSigPublic):
        self._authority = authority
        self._csca_pub = csca_pub
        self._doc_to_root: Dict[bytes, bytes] = {}   # document nullifier -> System-ID handle (binding; no PII)

    def _passes(self, att: DocumentAttestation) -> Optional[bool]:
        """Returns the cryptographic-flag if the document verifies, else None. Chip = cryptographic
        (True); vendor = labeled (False)."""
        if att.path is DocPath.CHIP:
            return True if verify_chip(att, self._csca_pub) else None
        return False if att.vendor_ok else None

    def certify(self, system_id_handle: bytes, att: DocumentAttestation, *, live_present: bool) -> RealIDResult:
        """Certify IFF a live human is present (holds this document), the document verifies, and
        the document isn't already bound to another System-ID. Issues an L1 credential (verified
        real human; identity NOT revealed). Stores only the document-nullifier -> System-ID
        binding; never the document / PII."""
        if not live_present:
            raise ValueError("liveness required — the live human must be present to bind to this document")
        cryptographic = self._passes(att)
        if cryptographic is None:
            raise ValueError("document did not verify")
        nul = document_nullifier(att.doc_unique)
        bound = self._doc_to_root.get(nul)
        if bound is not None and bound != system_id_handle:
            raise RealIDReuse("this document is already bound to another System-ID")
        self._doc_to_root[nul] = system_id_handle
        record, cred = self._authority.verify_and_issue(system_id_handle, AssuranceLevel.L1)
        return RealIDResult(record=record, credential=cred, cryptographic=cryptographic, doc_nullifier=nul)
