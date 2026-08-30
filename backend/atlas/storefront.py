"""Market storefront — where every product LIVES and TRANSACTS.

The market is the single home for all products; there is no "published but not in the market" mode.
To make a work available you LIST it on the market with a storefront: a COVER, BLURB, DESCRIPTION, and
PREVIEW/SAMPLES — as much of the product as the author chooses — while the FULL product stays GATED
behind free / buy / request-access. `open_full` releases the gated content only with a valid grant.

A product is found three ways, all pointing at the SAME market listing: (1) browse/search the market;
(2) a shareable LINK to the listing (`market_link` — where the item lives to be seen and picked); or
(3) that link shared directly in a message (the mailbox layer). The global register (atlas/ai/publish)
is the citeable CATALOG/discovery view over market listings + open works — it indexes what lives here;
it is not a separate bare-link destination.

ACQUISITION ALWAYS ROUTES THROUGH THE MARKET GATE. Wherever a work is surfaced (feed, spaces, messages,
web), the visible part is only the storefront (merchandising + preview); getting the FULL product goes
through `open_full` — a per-item grant from a market transaction (buy/request), OR a valid paid
SUBSCRIPTION covering that creator's media. There is no side door: nothing else releases the gated ref.

Ranking/eligibility (relevance + verified-human reviews, never pay-to-rank) is the marketplace's job
(marketplace.surface); this module owns the merchandising card, the author-chosen exposure boundary,
and the access gate. Under the persona handle (unlinkable), content stays on the author's node.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Dict, List, Optional, Tuple

from .crypto.primitives import H
from .crypto.sign import HybridSigKeypair, HybridSigPublic, sign, verify
from .keys.identity import handle_of


class StorefrontError(Exception):
    ...


class AccessDenied(StorefrontError):
    ...


class AccessMode(str, Enum):
    FREE = "free"          # the full product is free (still attributed) — no gate
    BUY = "buy"            # pay to unlock (payment receipt = the grant; via the payment module)
    REQUEST = "request"    # the author approves access on request (a signed grant)


@dataclass(frozen=True)
class Merchandising:
    """The author's CHOSEN exposure — everything a shopper may see before paying/requesting. Refs
    (cover/preview/gallery) point at freely-served sample content; the full product is elsewhere."""
    cover: str = ""            # content ref for the cover image
    blurb: str = ""            # one-line tagline
    description: str = ""      # long description
    preview: str = ""          # content ref for a FREE sample (first chapter / low-res / excerpt)
    gallery: Tuple[str, ...] = ()   # extra preview refs


@dataclass
class MarketListing:
    """A storefront listing for one work, signed under the author's persona handle. Carries the
    public merchandising AND the gated `full_content_ref` (never shown pre-access)."""
    work_id: bytes
    author: str                # persona handle (hex)
    public: HybridSigPublic
    title: str
    tags: Tuple[str, ...]
    license: str
    price_atlas: int
    access: AccessMode
    merch: Merchandising
    full_content_ref: str      # gated pointer to the full product (released only by open_full)
    sig: bytes = b""

    def id(self) -> bytes:
        return H(b"atlas/market-listing/id", self.work_id, self.author.encode())

    def body(self) -> bytes:
        return H(b"atlas/market-listing/v1", self.work_id, self.author.encode(), self.title.encode(),
                 " ".join(self.tags).encode(), self.license.encode(), str(self.price_atlas).encode(),
                 self.access.value.encode(), self.merch.cover.encode(), self.merch.blurb.encode(),
                 self.merch.description.encode(), self.merch.preview.encode(),
                 "|".join(self.merch.gallery).encode(), self.full_content_ref.encode())


def list_on_market(*, work_id: bytes, title: str, tags: Tuple[str, ...], license: str,
                   price_atlas: int, access: AccessMode, merch: Merchandising,
                   full_content_ref: str, signer: HybridSigKeypair) -> MarketListing:
    """List a work on the market under the signer's persona handle, with a merchandising card and an
    access mode. The full product stays gated behind `full_content_ref`."""
    author = handle_of(signer.public.encode()).hex()
    listing = MarketListing(work_id=work_id, author=author, public=signer.public, title=title,
                            tags=tuple(tags), license=license, price_atlas=price_atlas, access=access,
                            merch=merch, full_content_ref=full_content_ref)
    listing.sig = sign(signer, listing.body())
    return listing


def verify_market_listing(listing: MarketListing) -> bool:
    return (handle_of(listing.public.encode()).hex() == listing.author
            and verify(listing.public, listing.body(), listing.sig))


def storefront_view(listing: MarketListing) -> dict:
    """The PUBLIC, pre-purchase view: everything the author chose to expose — never the gated
    full_content_ref. This is what a shopper sees before paying/requesting."""
    return {
        "listing_id": listing.id().hex(), "author": listing.author, "title": listing.title,
        "tags": list(listing.tags), "license": listing.license, "price_atlas": listing.price_atlas,
        "access": listing.access.value, "cover": listing.merch.cover, "blurb": listing.merch.blurb,
        "description": listing.merch.description, "preview": listing.merch.preview,
        "gallery": list(listing.merch.gallery),
    }


@dataclass(frozen=True)
class AccessGrant:
    """Releases the full product to one requester. For REQUEST the author signs it; for BUY a payment
    receipt substitutes (wired via the payment module)."""
    listing_id: bytes
    requester: bytes
    grantor: HybridSigPublic
    sig: bytes

    def body(self) -> bytes:
        return H(b"atlas/market-access/v1", self.listing_id, self.requester)


def grant_access(author: HybridSigKeypair, listing: MarketListing, *, requester: bytes) -> AccessGrant:
    g = AccessGrant(listing_id=listing.id(), requester=requester, grantor=author.public, sig=b"")
    return replace(g, sig=sign(author, g.body()))


@dataclass(frozen=True)
class Subscription:
    """A paid media subscription — a time-bounded standing grant covering a creator's media, so a
    subscriber acquires their works without a per-item purchase. Issued by the creator (scope = the
    creator's persona handle). A broader media-pass authority would issue one over a media class."""
    subscriber: bytes
    scope: str                 # persona handle (hex) whose media this covers
    expires: int
    issuer: HybridSigPublic
    sig: bytes

    def body(self) -> bytes:
        return H(b"atlas/subscription/v1", self.subscriber, self.scope.encode(),
                 str(self.expires).encode())


def issue_subscription(issuer: HybridSigKeypair, *, subscriber: bytes, scope: str,
                       expires: int) -> Subscription:
    s = Subscription(subscriber=subscriber, scope=scope, expires=expires, issuer=issuer.public, sig=b"")
    return replace(s, sig=sign(issuer, s.body()))


def subscription_covers(sub: Subscription, listing: MarketListing, *, requester: bytes,
                        now: int) -> bool:
    """True iff this subscription is this requester's, not expired, covers this creator's media, and
    was issued by that creator."""
    return (sub.subscriber == requester and sub.expires > now and sub.scope == listing.author
            and sub.issuer.encode() == listing.public.encode()
            and verify(sub.issuer, sub.body(), sub.sig))


def open_full(listing: MarketListing, *, requester: bytes, grant: Optional[AccessGrant] = None,
              subscription: Optional[Subscription] = None, now: int = 0) -> str:
    """Return the gated full_content_ref iff acquisition is permitted — the single market gate.
    FREE opens for anyone; otherwise the requester needs EITHER a per-item grant (from a market
    buy/request, bound to this listing+requester+author) OR a valid subscription covering this
    creator's media. Nothing else releases it (AccessDenied)."""
    if listing.access is AccessMode.FREE:
        return listing.full_content_ref
    if (grant is not None and grant.listing_id == listing.id() and grant.requester == requester
            and grant.grantor.encode() == listing.public.encode()
            and verify(grant.grantor, grant.body(), grant.sig)):
        return listing.full_content_ref
    if subscription is not None and subscription_covers(subscription, listing, requester=requester,
                                                        now=now):
        return listing.full_content_ref
    raise AccessDenied("acquire through the market: buy, request access, or hold a valid subscription")


MARKET_LINK_BASE = "https://atlas.id/m/"        # a link to where an item LIVES in the market


def market_link(listing_id: bytes) -> str:
    """A shareable link to a market listing — the item's home, to be seen and picked. Share it in a
    message (the mailbox layer) or anywhere; it always resolves to the SAME market listing."""
    return MARKET_LINK_BASE + listing_id.hex()


def parse_market_link(url: str) -> Optional[bytes]:
    for base in (MARKET_LINK_BASE, "atlas://m/"):
        if url.startswith(base):
            try:
                return bytes.fromhex(url[len(base):].strip("/"))
            except ValueError:
                return None
    return None


def _tokens(s: str) -> set:
    return {t for t in "".join(c.lower() if c.isalnum() else " " for c in s).split() if t}


@dataclass
class Market:
    """Holds storefront listings; surfaces them by relevance (pull, not push). Public reads get the
    storefront_view only — the gated ref never leaves except via open_full."""
    _listings: Dict[bytes, MarketListing] = field(default_factory=dict)

    def list_item(self, listing: MarketListing) -> None:
        if not verify_market_listing(listing):
            raise StorefrontError("listing signature/handle invalid")
        self._listings[listing.id()] = listing

    def get(self, listing_id: bytes) -> Optional[MarketListing]:
        return self._listings.get(listing_id)

    def view(self, listing_id: bytes) -> Optional[dict]:
        """What a shared market link resolves to: the public storefront of the listing it lives at."""
        lst = self._listings.get(listing_id)
        return storefront_view(lst) if lst is not None else None

    def resolve_link(self, url: str) -> Optional[dict]:
        """Resolve a shared market link straight to the storefront it points at."""
        lid = parse_market_link(url)
        return self.view(lid) if lid is not None else None

    def find(self, query: str) -> List[dict]:
        """Storefront views of listings that genuinely match (title + tags + blurb overlap)."""
        q = _tokens(query)
        hits = [l for l in self._listings.values()
                if q & _tokens(l.title + " " + " ".join(l.tags) + " " + l.merch.blurb)]
        return [storefront_view(l) for l in hits]
