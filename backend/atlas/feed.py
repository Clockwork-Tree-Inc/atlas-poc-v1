"""Feed — a follow-based newsletter/Substack for all media types.

Two independent relationships, per the model:
  * FOLLOW (free) — you subscribe to someone's FEED. Their FREE posts appear in your timeline. No
    payment; following unlocks nothing gated.
  * SUBSCRIBE (paid) — a paid `storefront.Subscription` to their products/service. It unlocks their
    PAID posts here, and (in the market) their gated media without a per-item purchase.

So the feed is two-tier like Substack: FREE posts reach all followers; PAID posts reach only paid
subscribers. A post is authored + signed (provenance) and may carry a `market_link` to a listing —
but the feed only ever shows previews + links; acquiring any gated product still routes through the
market gate (buy or a valid subscription). One of the four sharing surfaces (market / messages /
spaces / feed).
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Dict, List, Sequence, Set, Tuple

from .crypto.primitives import H
from .crypto.sign import HybridSigKeypair, HybridSigPublic, sign, verify
from .keys.identity import handle_of
from .storefront import Subscription


class FeedError(Exception):
    ...


class PostTier(str, Enum):
    FREE = "free"          # reaches all followers
    PAID = "paid"          # reaches only paid subscribers (storefront.Subscription)


@dataclass
class FeedPost:
    """One authored feed entry, any media. `market_ref` optionally links to a market listing to
    acquire the full product; the post itself only carries text + preview refs."""
    author: str            # persona handle (hex)
    public: HybridSigPublic
    ts: int                # caller/device-supplied timestamp
    tier: PostTier
    caption: str
    media: Tuple[str, ...] = ()      # preview/media content refs
    market_ref: str = ""             # optional market_link to acquire a product
    sig: bytes = b""

    def body(self) -> bytes:
        return H(b"atlas/feed-post/v1", self.author.encode(), str(self.ts).encode(),
                 self.tier.value.encode(), self.caption.encode(), "|".join(self.media).encode(),
                 self.market_ref.encode())

    def id(self) -> bytes:
        return H(b"atlas/feed-post/id", self.public.encode(), self.body())


def make_post(author: HybridSigKeypair, *, ts: int, caption: str, tier: PostTier = PostTier.FREE,
              media: Sequence[str] = (), market_ref: str = "") -> FeedPost:
    p = FeedPost(author=handle_of(author.public.encode()).hex(), public=author.public, ts=ts,
                 tier=tier, caption=caption, media=tuple(media), market_ref=market_ref)
    p.sig = sign(author, p.body())
    return p


def verify_post(p: FeedPost) -> bool:
    return handle_of(p.public.encode()).hex() == p.author and verify(p.public, p.body(), p.sig)


def _sub_covers_author(s: Subscription, *, viewer: bytes, author_hex: str,
                       author_public: bytes, now: int) -> bool:
    return (s.subscriber == viewer and s.expires > now and s.scope == author_hex
            and s.issuer.encode() == author_public and verify(s.issuer, s.body(), s.sig))


@dataclass
class Feed:
    """The follow graph + authors' posts. FREE posts reach followers; PAID posts reach subscribers."""
    _posts: Dict[str, List[FeedPost]] = field(default_factory=dict)     # author hex -> posts
    _following: Dict[bytes, Set[str]] = field(default_factory=dict)     # follower handle -> authors

    def post(self, p: FeedPost) -> None:
        if not verify_post(p):
            raise FeedError("post signature/handle invalid")
        self._posts.setdefault(p.author, []).append(p)

    def follow(self, follower: bytes, author_hex: str) -> None:
        self._following.setdefault(follower, set()).add(author_hex)

    def unfollow(self, follower: bytes, author_hex: str) -> None:
        self._following.get(follower, set()).discard(author_hex)

    def following(self, follower: bytes) -> Set[str]:
        return set(self._following.get(follower, set()))

    def timeline(self, viewer: bytes, *, subscriptions: Sequence[Subscription] = (), now: int = 0,
                 limit: int = 50) -> List[FeedPost]:
        """Merged newest-first timeline from everyone `viewer` follows. FREE posts always show; a
        PAID post shows only if `viewer` holds a valid subscription covering that author."""
        subs = list(subscriptions)
        out: List[FeedPost] = []
        for author in self._following.get(viewer, set()):
            for p in self._posts.get(author, []):
                if p.tier is PostTier.FREE:
                    out.append(p)
                elif any(_sub_covers_author(s, viewer=viewer, author_hex=author,
                                            author_public=p.public.encode(), now=now) for s in subs):
                    out.append(p)
        out.sort(key=lambda p: p.ts, reverse=True)
        return out[:limit]
