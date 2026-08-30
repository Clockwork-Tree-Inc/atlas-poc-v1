"""Platform-reporting compliance store — the ONE retained legal-identity record the platform must
keep, walled off from everything else.

Canada's platform-reporting rules (in force from the 2024 tax year, following the OECD model)
require reporting a seller's name / address / tax id + per-period transaction totals to the revenue
agency yearly. That is precisely the queryable legal-identity-plus-history record the rest of ATLAS
is built to AVOID holding — so it is quarantined:

  * The MARKETPLACE only ever sees a PERSONA (a verified-human badge, reputation, delivery radius),
    never legal identity. Buyers need NO identity at all — reporting targets the money RECEIVER.
  * A reporting record is CREATED only when a seller CROSSES the threshold (the rules exempt sellers
    below ~30 activities AND ~C$3,000/yr) — so for most sellers the platform holds NOTHING.
  * The record is sealed WRITE-ONLY to the compliance service's key (hybrid KEM): the marketplace
    can CREATE a filing but has NO read path — it cannot open any filing, including ones it wrote.
  * Treat it as the highest-value breach target: one filing per seller, each independently sealed,
    so a single compromise is one seller, not the whole store.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional

from .crypto import kem
from .crypto.primitives import aead_decrypt, aead_encrypt

REPORT_MIN_ACTIVITIES = 30          # DAC7/OECD-style exemption floor (count)
REPORT_MIN_GROSS_CENTS = 300_000    # ~C$3,000
_AAD = b"atlas/compliance/report/v1"


@dataclass
class SellerActivity:
    """What the MARKETPLACE tracks for a seller — PERSONA only, never legal identity."""
    persona: str
    activities: int = 0
    gross_cents: int = 0
    filed: bool = False


def record_sale(a: SellerActivity, *, cents: int) -> None:
    a.activities += 1
    a.gross_cents += cents


def must_report(a: SellerActivity) -> bool:
    """Exempt ONLY if below BOTH thresholds; reportable if either is met (so a single large sale is
    reportable, and a high count of small sales is reportable)."""
    return a.activities >= REPORT_MIN_ACTIVITIES or a.gross_cents >= REPORT_MIN_GROSS_CENTS


@dataclass(frozen=True)
class ComplianceRecord:
    """A sealed filing — opaque to the marketplace. Only the compliance service can open it."""
    mlkem_ct: bytes
    x_eph_pk: bytes
    sealed: bytes


def maybe_file(a: SellerActivity, *, legal_identity: dict,
               compliance_pub: kem.HybridKEMPublic) -> Optional[ComplianceRecord]:
    """Create the reporting record IFF the seller crosses the threshold and hasn't been filed yet.
    Below threshold -> None (the platform stores NOTHING for that seller). The filing is sealed
    write-only to the compliance service; the marketplace keeps only the opaque `ComplianceRecord`
    and cannot read it back."""
    if a.filed or not must_report(a):
        return None
    enc = kem.encapsulate(compliance_pub)
    blob = json.dumps({"persona": a.persona, "legal_identity": legal_identity,
                        "activities": a.activities, "gross_cents": a.gross_cents},
                       sort_keys=True).encode("utf-8")
    rec = ComplianceRecord(enc.mlkem_ct, enc.x25519_eph_pk, aead_encrypt(enc.shared, blob, aad=_AAD))
    a.filed = True
    return rec


def open_report(rec: ComplianceRecord, *, compliance_kp: kem.HybridKEMKeypair) -> dict:
    """ONLY the compliance service (holding the KEM secret) can read a filing — the marketplace,
    holding just the public key, never can."""
    shared = kem.decapsulate(compliance_kp, rec.mlkem_ct, rec.x_eph_pk)
    return json.loads(aead_decrypt(shared, rec.sealed, aad=_AAD))
