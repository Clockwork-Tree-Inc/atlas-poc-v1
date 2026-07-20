"""Market & Feed primitives (Phase B #2) — shapes over Space.

MARKET — "a review is a receipt." No verified purchase -> no review, PROVABLY. A `Review` is valid
ONLY when backed by a seller-signed `Receipt` binding THIS reviewer to a purchase of THIS item.
Verified human + verified purchase + cryptographic binding = a review that cannot be faked or bought
(the Vouch; Public-ledgered by the caller).

FEED — `Endorsement`s are signed statements by orgs/personas over a target (a post / an author). The
platform SURFACES them (verifiable), it never ranks them: the author curates their `top3` — user
choice, no algorithm — and viewers verify each against the endorser's key and assess for themselves.

Not new crypto — signatures over domain-separated, length-prefixed bodies (same discipline as the
authority engine).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence

from ..crypto.primitives import H
from ..crypto.sign import HybridSigKeypair, HybridSigPublic, sign, verify

_RECEIPT_DOMAIN = b"atlas/market/receipt/v1"
_REVIEW_DOMAIN = b"atlas/market/review/v1"
_ENDORSE_DOMAIN = b"atlas/market/endorse/v1"


def _lp(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


# --------------------------------------------------------------------------- market: receipt + review
@dataclass
class Receipt:
    """Seller-signed proof that `buyer` (a verified human) purchased `item`. The entry ticket to a
    review — a review with no receipt is not a review."""

    seller: HybridSigPublic
    buyer: HybridSigPublic
    item: bytes
    epoch: int
    sig: bytes = b""

    def _body(self) -> bytes:
        return b"".join([_RECEIPT_DOMAIN, _lp(self.seller.encode()), _lp(self.buyer.encode()),
                         _lp(self.item), self.epoch.to_bytes(8, "big")])


def issue_receipt(seller_kp: HybridSigKeypair, *, buyer: HybridSigPublic, item: bytes,
                  epoch: int) -> Receipt:
    r = Receipt(seller=seller_kp.public, buyer=buyer, item=item, epoch=epoch)
    r.sig = sign(seller_kp, r._body())
    return r


@dataclass
class Review:
    """A reviewer-signed rating of `item`. Valid ONLY with a matching Receipt (see verify_review)."""

    reviewer: HybridSigPublic
    item: bytes
    rating: int
    content_hash: bytes
    epoch: int
    sig: bytes = b""

    def _body(self) -> bytes:
        return b"".join([_REVIEW_DOMAIN, _lp(self.reviewer.encode()), _lp(self.item),
                         self.rating.to_bytes(4, "big"), _lp(self.content_hash),
                         self.epoch.to_bytes(8, "big")])


def write_review(reviewer_kp: HybridSigKeypair, *, item: bytes, rating: int, content: bytes,
                 epoch: int) -> Review:
    r = Review(reviewer=reviewer_kp.public, item=item, rating=rating,
               content_hash=H(b"atlas/market/review-content", content), epoch=epoch)
    r.sig = sign(reviewer_kp, r._body())
    return r


def verify_review(review: Review, receipt: Receipt, *, seller_public: HybridSigPublic,
                  is_verified_human=None) -> bool:
    """NO PURCHASE -> NO REVIEW. A review is valid iff: the reviewer signed it; the seller signed a
    receipt for THIS item purchased by THIS reviewer. Reviews cannot be faked (no reviewer key) or
    bought/astroturfed (no receipt => no review).

    The MARKET REQUIRES A REAL-PERSON PSEUDONYM (accountable pseudonymity): a marketplace runs in a
    VERIFIED_PERSON space, and passing `is_verified_human` enforces here that the reviewer is a
    personhood-backed pseudonym (one real accountable human, real-ID hidden) — so a review is a
    verified purchase BY a verified person, not a farm of sockpuppets."""
    if not verify(review.reviewer, review._body(), review.sig):
        return False
    if not verify(seller_public, receipt._body(), receipt.sig):
        return False
    if receipt.item != review.item:
        return False
    if receipt.buyer.encode() != review.reviewer.encode():
        return False
    if is_verified_human is not None and not is_verified_human(review.reviewer.encode()):
        return False                                          # market: reviewer must be a real person
    return True


# --------------------------------------------------------------------------- feed: endorsements + top3
@dataclass
class Endorsement:
    """A signed endorsement by `endorser` over `target` (a post commitment or author handle). The
    platform surfaces it verifiably; it never ranks."""

    endorser: HybridSigPublic
    target: bytes
    epoch: int
    sig: bytes = b""

    def _body(self) -> bytes:
        return b"".join([_ENDORSE_DOMAIN, _lp(self.endorser.encode()), _lp(self.target),
                         self.epoch.to_bytes(8, "big")])


def endorse(endorser_kp: HybridSigKeypair, *, target: bytes, epoch: int) -> Endorsement:
    e = Endorsement(endorser=endorser_kp.public, target=target, epoch=epoch)
    e.sig = sign(endorser_kp, e._body())
    return e


def verify_endorsement(e: Endorsement) -> bool:
    return verify(e.endorser, e._body(), e.sig)


def top3(endorsements: Sequence[Endorsement], chosen: Sequence[bytes]) -> List[Endorsement]:
    """The AUTHOR curates which endorsements to feature — user choice, no algorithm. Returns up to 3
    VALID endorsements whose endorser (by encoded key) is in `chosen`, in the author's chosen order.
    Invalid or unchosen endorsements are dropped; nothing is ranked by the platform."""
    valid = {e.endorser.encode(): e for e in endorsements if verify_endorsement(e)}
    out: List[Endorsement] = []
    for enc in chosen:
        if enc in valid and valid[enc] not in out:
            out.append(valid[enc])
        if len(out) == 3:
            break
    return out
