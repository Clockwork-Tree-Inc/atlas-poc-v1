"""Paid attention — stores PAY you to look at their products, instead of stealing your attention.
The inverse of surveillance advertising: opt-in, consensual, compensated. PoLE is what makes it
possible — a reward is only paid to a proven LIVE HUMAN who actually attended (a valid presence
receipt covering the offer window), exactly once per human (a per-offer nullifier). Bots can't farm
it: no live-human presence, no receipt, no pay; one human, one redemption.

  store signs an OFFER (view product X -> earn R, valid [start,end])
    -> a human ATTENDS and CLAIMS, binding the claim to a presence receipt + a one-per-human nullifier
    -> the ledger pays R once; the human spends it on marketplace listings (closed-loop currency)

Composes `presence_receipt` (proof a live human attended) + signatures + nullifier dedup. No new
crypto. Reference of record. Swift parity: ios/AtlasCore/Sources/AtlasCore/Economy/Attention.swift.
"""
from __future__ import annotations

from dataclasses import dataclass, replace

from ..crypto.primitives import H
from ..crypto.sign import HybridSigKeypair, HybridSigPublic, sign, verify
from .presence_receipt import PresenceReceipt, verify_receipt

_OFFER = b"atlas/attention-offer/v1"
_CLAIM = b"atlas/attention-claim/v1"
_NULL = b"atlas/attention-nullifier/v1"


class AttentionError(Exception):
    pass


def _lp(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


def _be8(n: int) -> bytes:
    return int(n).to_bytes(8, "big")


@dataclass(frozen=True)
class AttentionOffer:
    store: HybridSigPublic          # the store's key (a Real-ID + registration-verified org in prod)
    product_id: bytes
    reward: int                     # paid in the internal currency
    window_start: int               # the offer is attendable within this window
    window_end: int
    sig: bytes = b""

    def body(self) -> bytes:
        return b"".join([_OFFER, _lp(self.store.encode()), _lp(self.product_id), _be8(self.reward),
                         _be8(self.window_start), _be8(self.window_end)])

    def id(self) -> bytes:
        return H(b"atlas/attention-offer-id", self.body())


def make_offer(store_kp: HybridSigKeypair, *, product_id: bytes, reward: int,
               window_start: int, window_end: int) -> AttentionOffer:
    if reward <= 0:
        raise AttentionError("reward must be > 0")
    if window_end < window_start:
        raise AttentionError("window_end < window_start")
    o = AttentionOffer(store=store_kp.public, product_id=product_id, reward=reward,
                       window_start=window_start, window_end=window_end)
    return replace(o, sig=sign(store_kp, o.body()))


def verify_offer(o: AttentionOffer) -> bool:
    return o.reward > 0 and o.window_end >= o.window_start and verify(o.store, o.body(), o.sig)


def attention_nullifier(subject: bytes, offer_id: bytes) -> bytes:
    """One redemption per persona per offer — the same (subject, offer) always yields the same tag."""
    return H(_NULL, _lp(subject), _lp(offer_id))


@dataclass(frozen=True)
class AttentionClaim:
    offer_id: bytes
    subject: bytes                  # the attending persona handle (bound to the receipt)
    receipt: PresenceReceipt        # proof a live human was present during the offer window
    nullifier: bytes
    signer: HybridSigPublic         # the persona key that attended (must be a receipt co-signer)
    sig: bytes = b""

    def body(self) -> bytes:
        return b"".join([_CLAIM, _lp(self.offer_id), _lp(self.subject),
                         _lp(self.receipt.id()), _lp(self.nullifier), _lp(self.signer.encode())])


def claim_attention(persona_kp: HybridSigKeypair, *, offer: AttentionOffer,
                    receipt: PresenceReceipt) -> AttentionClaim:
    """A human who attended builds a claim bound to their presence receipt + a one-per-human nullifier."""
    c = AttentionClaim(offer_id=offer.id(), subject=receipt.subject, receipt=receipt,
                       nullifier=attention_nullifier(receipt.subject, offer.id()),
                       signer=persona_kp.public)
    return replace(c, sig=sign(persona_kp, c.body()))


def _overlaps(r: PresenceReceipt, o: AttentionOffer) -> bool:
    return not (r.window_end < o.window_start or r.window_start > o.window_end)


def verify_claim(offer: AttentionOffer, claim: AttentionClaim, *, min_signers: int = 1) -> bool:
    """A claim is payable iff: the offer is validly signed; the claim is for THIS offer; the presence
    receipt is valid (a real live human), bound to the claim's subject, and its window overlaps the
    offer's; the nullifier is correctly derived (one per human per offer); and the claim is signed by
    a key that CO-SIGNED the presence receipt (proving control of the attending persona)."""
    if not verify_offer(offer):
        return False
    if claim.offer_id != offer.id():
        return False
    if claim.receipt.subject != claim.subject:
        return False
    if not verify_receipt(claim.receipt, min_signers=min_signers):
        return False
    if not _overlaps(claim.receipt, offer):
        return False
    if claim.nullifier != attention_nullifier(claim.subject, offer.id()):
        return False
    signer_enc = claim.signer.encode()
    if signer_enc not in {s.encode() for s in claim.receipt.signers}:
        return False                                       # the claimer must be a presence co-signer
    return verify(claim.signer, claim.body(), claim.sig)


class AttentionLedger:
    """Pays each valid claim ONCE — the anti-farming gate. Records paid nullifiers."""

    def __init__(self) -> None:
        self._paid: dict[bytes, int] = {}

    def redeem(self, offer: AttentionOffer, claim: AttentionClaim, *, min_signers: int = 1) -> int:
        if not verify_claim(offer, claim, min_signers=min_signers):
            raise AttentionError("invalid claim — not a proven live human attending this offer")
        if claim.nullifier in self._paid:
            raise AttentionError("already redeemed — one reward per human per offer")
        self._paid[claim.nullifier] = offer.reward
        return offer.reward

    def total_paid(self) -> int:
        return sum(self._paid.values())
