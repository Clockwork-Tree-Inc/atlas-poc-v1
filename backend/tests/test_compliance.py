"""Platform-reporting compliance store (PART 4): created only at the threshold, sealed write-only to
the compliance service, no read path from the marketplace."""
import pytest

from atlas import compliance
from atlas.crypto import kem

LEGAL = {"name": "A. Seller", "address": "…", "tax_id": "123-456-789"}


def test_below_threshold_platform_holds_nothing():
    svc = kem.generate_keypair()
    a = compliance.SellerActivity(persona="nightowl")
    for _ in range(10):
        compliance.record_sale(a, cents=5_000)      # 10 sales, C$500 — well under both floors
    assert not compliance.must_report(a)
    assert compliance.maybe_file(a, legal_identity=LEGAL, compliance_pub=svc.public) is None
    assert not a.filed


def test_crossing_by_count_or_by_gross_files_once():
    svc = kem.generate_keypair()
    # by COUNT: 30 tiny sales
    a = compliance.SellerActivity(persona="nightowl")
    for _ in range(30):
        compliance.record_sale(a, cents=100)
    rec = compliance.maybe_file(a, legal_identity=LEGAL, compliance_pub=svc.public)
    assert rec is not None and a.filed
    # idempotent — a second call does not re-file
    assert compliance.maybe_file(a, legal_identity=LEGAL, compliance_pub=svc.public) is None

    # by GROSS: a single large sale
    b = compliance.SellerActivity(persona="dayowl")
    compliance.record_sale(b, cents=500_000)         # one C$5,000 sale
    assert compliance.maybe_file(b, legal_identity=LEGAL, compliance_pub=svc.public) is not None


def test_marketplace_cannot_read_a_filing_only_the_service_can():
    svc = kem.generate_keypair()
    a = compliance.SellerActivity(persona="nightowl", activities=40, gross_cents=400_000)
    rec = compliance.maybe_file(a, legal_identity=LEGAL, compliance_pub=svc.public)
    assert rec is not None

    # the marketplace (a DIFFERENT keypair — it never holds the compliance secret) cannot open it
    marketplace = kem.generate_keypair()
    with pytest.raises(Exception):
        compliance.open_report(rec, compliance_kp=marketplace)

    # only the compliance service, holding the KEM secret, reads the legal identity + totals
    got = compliance.open_report(rec, compliance_kp=svc)
    assert got["persona"] == "nightowl"
    assert got["legal_identity"] == LEGAL
    assert got["activities"] == 40 and got["gross_cents"] == 400_000
