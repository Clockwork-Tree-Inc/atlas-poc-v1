"""Organization access gate + anti-ad surfacing: payment GATES eligibility, never rank; pull-not-push
(only genuine matches surface); reviews break ties (not payment); unpaid/out-of-region excluded."""

import os

from atlas.keys.identity import PseudonymTier, build_identity_tree
from atlas.marketplace import (Organization, EntityClass, is_surfaceable, list_item, surface,
                               verify_listing)


def _biz(name, region="us", paid=True, conformant=True):
    ident = build_identity_tree(os.urandom(32)).profile(name, PseudonymTier.PUBLIC).identity
    b = Organization(handle=ident.handle, entity_class=EntityClass.FOR_PROFIT, region=region,
                 paid=paid, conformant=conformant)
    return ident, b


def test_access_gate_requires_paid_and_conformant():
    _ident, b = _biz("shop")
    assert is_surfaceable(b)
    b.paid = False
    assert not is_surfaceable(b)
    b.paid = True
    b.conformant = False
    assert not is_surfaceable(b)


def test_surface_is_pull_and_relevance_ranked_not_pay_to_rank():
    good_id, good = _biz("boots")
    weak_id, weak = _biz("candles")
    good_listing = list_item(good_id, "Waterproof hiking boots", ["boots", "hiking", "waterproof"], 50, "us")
    weak_listing = list_item(weak_id, "Scented candle", ["candle", "home"], 20, "us")
    assert verify_listing(good_listing) and verify_listing(weak_listing)
    # both paid+conformant; the better MATCH surfaces, the non-matching candle is not shown at all
    assert surface("hiking boots", "us", [weak_listing, good_listing], [good, weak]) == [good_listing]


def test_unpaid_or_out_of_region_excluded():
    a_id, a = _biz("a", region="us")
    b_id, b = _biz("b", region="us", paid=False)
    la = list_item(a_id, "red boots", ["boots"], 10, "us")
    lb = list_item(b_id, "blue boots", ["boots"], 10, "us")
    assert surface("boots", "us", [la, lb], [a, b]) == [la]      # unpaid b excluded
    assert surface("boots", "eu", [la], [a]) == []               # region mismatch excluded


def test_reviews_break_ties_not_payment():
    x_id, x = _biz("x")
    y_id, y = _biz("y")
    lx = list_item(x_id, "boots", ["boots"], 10, "us")
    ly = list_item(y_id, "boots", ["boots"], 10, "us")
    # equal relevance; y has better verified-human reviews -> y ranks first (reviews, not payment)
    assert surface("boots", "us", [lx, ly], [x, y], review_net={ly.id(): 5, lx.id(): 1}) == [ly, lx]


def test_forged_listing_rejected():
    real_id, real = _biz("real")
    attacker_id, _ = _biz("atk")
    lst = list_item(attacker_id, "boots", ["boots"], 10, "us")
    lst.business = real.handle                 # claim someone else's handle -> handle != handle_of(public)
    assert not verify_listing(lst)
    assert surface("boots", "us", [lst], [real]) == []
