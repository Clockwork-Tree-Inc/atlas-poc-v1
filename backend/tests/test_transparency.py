"""Organization transparency: privacy for people, accountability for businesses. Businesses must be
identified and their books are public + tamper-evident; customers stay pseudonymous."""
import pytest

from atlas.economy import (
    Coin,
    IdentityRequiredError,
    TransparencyLedger,
    business_listing_fee,
    business_sale,
)


def _coin(buyer, amt):
    c = Coin()
    c._mint(buyer, amt)
    return c


def test_unidentified_business_cannot_operate():
    led = TransparencyLedger()
    with pytest.raises(IdentityRequiredError):
        led.register_business("biz:shady", identified=False)      # no anonymous businesses
    with pytest.raises(IdentityRequiredError):
        led.record(business="biz:x", kind="sale", amount=1, fee=0,
                   counterparty="p:anon", epoch=1)                 # unregistered -> refused


def test_business_sale_records_transparently_customer_stays_private():
    c = _coin("p:anon-shopper", 10_000)
    led = TransparencyLedger()
    led.register_business("biz:healthfoods", identified=True)
    sale = business_sale(c, led, seller="biz:healthfoods", buyer="p:anon-shopper",
                         item=b"kombucha", amount=1_000, epoch=1, fee_bp=300)
    assert sale.fee == 30 and c.balance("biz:healthfoods") == 970
    books = led.audit("biz:healthfoods")
    assert len(books) == 1
    e = books[0]
    assert e.business == "biz:healthfoods" and e.amount == 1_000 and e.fee == 30
    assert e.counterparty == "p:anon-shopper"      # a pseudonym — the person stays private
    assert led.verify_chain()


def test_books_are_tamper_evident():
    led = TransparencyLedger()
    led.register_business("biz:a", identified=True)
    led.record(business="biz:a", kind="sale", amount=100, fee=3, counterparty="p:x", epoch=1)
    led.record(business="biz:a", kind="sale", amount=200, fee=6, counterparty="p:y", epoch=1)
    assert led.verify_chain()
    # tamper with the first entry's amount -> chain breaks
    tampered = led._entries[0].__class__(business="biz:a", kind="sale", amount=999, fee=3,
                                         counterparty="p:x", epoch=1, prev=led._entries[0].prev)
    led._entries[0] = tampered
    assert not led.verify_chain()


def test_listing_fee_is_recorded_and_tithed():
    c = _coin("biz:a", 500)
    led = TransparencyLedger()
    led.register_business("biz:a", identified=True)
    paid = business_listing_fee(c, led, business="biz:a", amount=200, epoch=1)
    assert paid == 200 and c.balance("tithe") == 200
    assert led.audit("biz:a")[0].kind == "listing_fee"


def test_audit_is_public_across_all_businesses():
    c = _coin("p:buyer", 10_000)
    led = TransparencyLedger()
    for b in ("biz:a", "biz:b"):
        led.register_business(b, identified=True)
    business_sale(c, led, seller="biz:a", buyer="p:buyer", item=b"x", amount=1000, epoch=1)
    business_sale(c, led, seller="biz:b", buyer="p:buyer", item=b"y", amount=1000, epoch=1)
    assert len(led.audit()) == 2                    # everything auditable
    assert len(led.audit("biz:a")) == 1
