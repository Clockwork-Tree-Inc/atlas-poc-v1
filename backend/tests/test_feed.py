"""Feed (#33): follow (free) gives you someone's FREE posts; a paid subscription unlocks their PAID
posts. Two-tier newsletter for all media; acquisition of gated products still routes through market."""

import pytest

from atlas.crypto.sign import generate_sig_keypair
from atlas.feed import Feed, FeedError, PostTier, make_post, verify_post
from atlas.keys.identity import handle_of
from atlas.storefront import issue_subscription


def _author():
    kp = generate_sig_keypair()
    return kp, handle_of(kp.public.encode()).hex()


def test_post_is_signed_and_forgery_rejected():
    kp, hexh = _author()
    p = make_post(kp, ts=10, caption="hello world")
    assert p.author == hexh and verify_post(p)
    p.caption = "tampered"
    assert not verify_post(p)


def test_follow_gives_free_posts_newest_first():
    kp, author = _author()
    viewer = b"viewer-1"
    feed = Feed()
    feed.post(make_post(kp, ts=1, caption="first"))
    feed.post(make_post(kp, ts=3, caption="third"))
    feed.post(make_post(kp, ts=2, caption="second"))
    assert feed.timeline(viewer) == []                 # not following -> empty
    feed.follow(viewer, author)
    assert [p.caption for p in feed.timeline(viewer)] == ["third", "second", "first"]
    feed.unfollow(viewer, author)
    assert feed.timeline(viewer) == []


def test_paid_posts_hidden_without_subscription_shown_with():
    kp, author = _author()
    viewer = b"viewer-1"
    feed = Feed()
    feed.follow(viewer, author)
    feed.post(make_post(kp, ts=1, caption="free note", tier=PostTier.FREE))
    feed.post(make_post(kp, ts=2, caption="subscriber deep-dive", tier=PostTier.PAID,
                        market_ref="https://atlas.id/m/abcd"))
    # following only -> sees the free post, not the paid one
    assert [p.caption for p in feed.timeline(viewer)] == ["free note"]
    # a paid subscription to this author -> unlocks the paid post
    sub = issue_subscription(kp, subscriber=viewer, scope=author, expires=1000)
    got = [p.caption for p in feed.timeline(viewer, subscriptions=[sub], now=100)]
    assert got == ["subscriber deep-dive", "free note"]
    # expired subscription -> paid post hidden again
    assert [p.caption for p in feed.timeline(viewer, subscriptions=[sub], now=2000)] == ["free note"]


def test_subscription_for_other_creator_does_not_unlock():
    kp, author = _author()
    other_kp, _other = _author()
    viewer = b"viewer-1"
    feed = Feed()
    feed.follow(viewer, author)
    feed.post(make_post(kp, ts=1, caption="paid", tier=PostTier.PAID))
    wrong = issue_subscription(other_kp, subscriber=viewer, scope=_other, expires=1000)
    assert feed.timeline(viewer, subscriptions=[wrong], now=100) == []   # wrong creator's sub


def test_forged_post_rejected_on_post():
    kp, _h = _author()
    feed = Feed()
    p = make_post(kp, ts=1, caption="ok")
    p.caption = "hijacked"
    with pytest.raises(FeedError):
        feed.post(p)
