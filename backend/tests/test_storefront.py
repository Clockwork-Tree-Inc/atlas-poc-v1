"""Market storefront: list a work with a merchandising card (cover/blurb/description/preview) that a
shopper sees BEFORE paying, while the full product stays gated behind buy/request-access."""

import pytest

from atlas.crypto.sign import generate_sig_keypair
from atlas.keys.identity import handle_of
from atlas.storefront import (
    AccessDenied,
    AccessMode,
    Market,
    Merchandising,
    StorefrontError,
    grant_access,
    issue_subscription,
    list_on_market,
    market_link,
    open_full,
    parse_market_link,
    storefront_view,
    verify_market_listing,
)


def _seller():
    kp = generate_sig_keypair()
    return kp, handle_of(kp.public.encode())


def _listing(kp, *, access=AccessMode.REQUEST, ref="vault://full/book1"):
    return list_on_market(work_id=b"book1", title="Tide Atlas", tags=("tide", "book"),
                          license="content:quote", price_atlas=30, access=access,
                          merch=Merchandising(cover="vault://cover", blurb="Every tide, mapped",
                                              description="A full-color guide to coastal tides.",
                                              preview="vault://chapter1", gallery=("vault://pg2",)),
                          full_content_ref=ref, signer=kp)


def test_listing_is_signed_under_persona_handle():
    kp, handle = _seller()
    lst = _listing(kp)
    assert lst.author == handle.hex()
    assert verify_market_listing(lst)


def test_storefront_view_exposes_merchandising_not_the_full_product():
    kp, _h = _seller()
    view = storefront_view(_listing(kp))
    assert view["cover"] == "vault://cover"
    assert view["blurb"] == "Every tide, mapped"
    assert view["preview"] == "vault://chapter1"      # the free sample is exposed
    assert view["description"].startswith("A full-color")
    assert "full_content_ref" not in view             # the gated product is NEVER in the shop view


def test_gated_product_needs_a_grant():
    kp, _h = _seller()
    buyer = b"buyer-handle"
    lst = _listing(kp, access=AccessMode.REQUEST)
    with pytest.raises(AccessDenied):                 # no grant -> gated
        open_full(lst, requester=buyer)
    grant = grant_access(kp, lst, requester=buyer)    # author approves this buyer
    assert open_full(lst, requester=buyer, grant=grant) == "vault://full/book1"


def test_grant_is_bound_to_listing_and_requester():
    kp, _h = _seller()
    lst = _listing(kp)
    grant = grant_access(kp, lst, requester=b"alice")
    with pytest.raises(AccessDenied):                 # a grant for alice doesn't open for bob
        open_full(lst, requester=b"bob", grant=grant)
    # a grant signed by someone who isn't the author is rejected
    other_kp, _ = _seller()
    forged = grant_access(other_kp, lst, requester=b"alice")
    with pytest.raises(AccessDenied):
        open_full(lst, requester=b"alice", grant=forged)


def test_free_access_needs_no_grant():
    kp, _h = _seller()
    free = _listing(kp, access=AccessMode.FREE, ref="vault://full/free")
    assert open_full(free, requester=b"anyone") == "vault://full/free"


def test_subscription_opens_creator_media_without_per_item_purchase():
    kp, handle = _seller()
    sub_handle = b"subscriber-1"
    lst = _listing(kp, access=AccessMode.BUY)
    with pytest.raises(AccessDenied):                              # no grant, no sub -> gated
        open_full(lst, requester=sub_handle, now=100)
    sub = issue_subscription(kp, subscriber=sub_handle, scope=handle.hex(), expires=1000)
    assert open_full(lst, requester=sub_handle, subscription=sub, now=100) == "vault://full/book1"
    with pytest.raises(AccessDenied):                              # expired subscription
        open_full(lst, requester=sub_handle, subscription=sub, now=2000)
    other = issue_subscription(kp, subscriber=b"someone-else", scope=handle.hex(), expires=1000)
    with pytest.raises(AccessDenied):                              # not this requester's sub
        open_full(lst, requester=sub_handle, subscription=other, now=100)
    other_kp, other_handle = _seller()                             # sub to a DIFFERENT creator
    wrong_scope = issue_subscription(other_kp, subscriber=sub_handle, scope=other_handle.hex(), expires=1000)
    with pytest.raises(AccessDenied):
        open_full(lst, requester=sub_handle, subscription=wrong_scope, now=100)


def test_market_link_resolves_to_where_the_item_lives():
    kp, _h = _seller()
    m = Market()
    lst = _listing(kp)
    m.list_item(lst)
    link = market_link(lst.id())                       # a shareable link (share it in a message, etc.)
    assert parse_market_link(link) == lst.id()
    view = m.resolve_link(link)                        # ...always resolves to the SAME market listing
    assert view["title"] == "Tide Atlas" and "full_content_ref" not in view
    assert m.resolve_link("https://atlas.id/m/deadbeef") is None   # unknown -> nothing


def test_market_surfaces_by_relevance_and_rejects_forged_listings():
    kp, _h = _seller()
    m = Market()
    m.list_item(_listing(kp))
    assert m.find("tide")                              # matches title/tags/blurb
    assert m.find("spaceship") == []                   # no genuine match -> not surfaced
    # tamper the listing after signing -> rejected on list
    bad = _listing(kp)
    bad.title = "hijacked"
    with pytest.raises(StorefrontError):
        m.list_item(bad)
