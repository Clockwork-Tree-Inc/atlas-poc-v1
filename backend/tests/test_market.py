"""Market (receipt-gated review) + Feed (endorsements, author-curated top-3)."""

import pytest

from atlas.crypto.sign import keypair_from_seed
from atlas.spaces.market import (
    Endorsement, endorse, issue_receipt, top3, verify_endorsement, verify_review, write_review,
)


def kp(n):
    return keypair_from_seed(bytes([n]) * 32)


SELLER, BUYER, OTHER = kp(1), kp(2), kp(3)
ITEM = b"widget-42"


# --------------------------------------------------------------------------- market
def test_review_with_matching_receipt_verifies():
    receipt = issue_receipt(SELLER, buyer=BUYER.public, item=ITEM, epoch=1)
    review = write_review(BUYER, item=ITEM, rating=5, content=b"great", epoch=2)
    assert verify_review(review, receipt, seller_public=SELLER.public) is True


def test_no_purchase_no_review():
    # OTHER never bought ITEM — presenting BUYER's receipt doesn't validate OTHER's review.
    receipt_for_buyer = issue_receipt(SELLER, buyer=BUYER.public, item=ITEM, epoch=1)
    astroturf = write_review(OTHER, item=ITEM, rating=5, content=b"fake", epoch=2)
    assert verify_review(astroturf, receipt_for_buyer, seller_public=SELLER.public) is False


def test_review_for_wrong_item_rejected():
    receipt = issue_receipt(SELLER, buyer=BUYER.public, item=b"other-item", epoch=1)
    review = write_review(BUYER, item=ITEM, rating=5, content=b"x", epoch=2)
    assert verify_review(review, receipt, seller_public=SELLER.public) is False


def test_forged_receipt_rejected():
    receipt = issue_receipt(OTHER, buyer=BUYER.public, item=ITEM, epoch=1)      # not the real seller
    review = write_review(BUYER, item=ITEM, rating=5, content=b"x", epoch=2)
    assert verify_review(review, receipt, seller_public=SELLER.public) is False


def test_tampered_review_rejected():
    receipt = issue_receipt(SELLER, buyer=BUYER.public, item=ITEM, epoch=1)
    review = write_review(BUYER, item=ITEM, rating=5, content=b"x", epoch=2)
    review.rating = 1                                                           # tamper after signing
    assert verify_review(review, receipt, seller_public=SELLER.public) is False


def test_market_requires_verified_person():
    # The market runs in a VERIFIED_PERSON space: a review by a non-personhood reviewer is rejected.
    receipt = issue_receipt(SELLER, buyer=BUYER.public, item=ITEM, epoch=1)
    review = write_review(BUYER, item=ITEM, rating=5, content=b"great", epoch=2)
    verified = {BUYER.public.encode()}
    assert verify_review(review, receipt, seller_public=SELLER.public,
                         is_verified_human=lambda enc: enc in verified) is True
    assert verify_review(review, receipt, seller_public=SELLER.public,
                         is_verified_human=lambda enc: False) is False          # not a real person


# --------------------------------------------------------------------------- feed / endorsements
def test_endorse_and_verify():
    e = endorse(kp(10), target=b"post-1", epoch=1)
    assert verify_endorsement(e)
    e.epoch = 999                                                              # tamper
    assert not verify_endorsement(e)


def test_top3_is_author_curated_and_capped():
    es = [endorse(kp(n), target=b"post-1", epoch=1) for n in (10, 11, 12, 13)]
    # author features these endorsers, in this order (4 chosen, capped to 3)
    chosen = [kp(12).public.encode(), kp(10).public.encode(), kp(13).public.encode(), kp(11).public.encode()]
    featured = top3(es, chosen)
    assert [e.endorser.encode() for e in featured] == chosen[:3]               # author's order, max 3


def test_top3_drops_invalid_and_unchosen():
    good = endorse(kp(10), target=b"p", epoch=1)
    forged = Endorsement(endorser=kp(11).public, target=b"p", epoch=1)          # unsigned -> invalid
    featured = top3([good, forged], [kp(11).public.encode(), kp(10).public.encode()])
    assert [e.endorser.encode() for e in featured] == [kp(10).public.encode()]  # forged dropped
