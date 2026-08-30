"""Organization access gate + anti-ad SURFACING.

Businesses are the paying customers: they pay a tithe/membership to be ELIGIBLE to be surfaced,
and must pass conformance (the non-harm bar) and be region-eligible. But payment buys
ELIGIBILITY, NEVER RANK. When a user's agent asks for something they NEED, listings are ranked by
genuine relevance to the need + verified-human review score, and only listings that actually MATCH
are shown (pull, not push — no ads, no profiling, no pay-to-rank).

Fee collection / revenue-split settlement is money and lives on the private economy branch; here
`paid` is the stub for "membership active".
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Sequence

from .crypto.primitives import H
from .crypto.sign import HybridSigPublic, sign, verify
from .keys.identity import Child, handle_of


class EntityClass(Enum):
    """The only entity classes (no protected-trait / no religious-org classes — Inv 8).

    Three top-level kinds: INDIVIDUAL (a verified live human), ORGANIZATION (NONPROFIT / FOR_PROFIT —
    a registered collective legal entity; fiscal status is the sub-type, and room remains for
    government / cooperative / DAO later), and AGENT (an AI/autonomous actor). An AGENT is never a
    root: it always acts under a delegation from a principal that ultimately roots in an enrolled
    human/organization (see `agent_delegation`). Humans draw PoLE/UBI; organizations transact but
    don't; agents act only on behalf of a principal."""
    INDIVIDUAL = "individual"
    NONPROFIT = "nonprofit"
    FOR_PROFIT = "for_profit"
    AGENT = "agent"

    @property
    def is_organization(self) -> bool:
        """Organizations = the registered collective-entity classes (fiscal status is the sub-type)."""
        return self in (EntityClass.NONPROFIT, EntityClass.FOR_PROFIT)

    @property
    def can_be_principal(self) -> bool:
        """Only a human or an organization can ROOT authority for an agent — never another agent."""
        return self is not EntityClass.AGENT


@dataclass
class Organization:
    handle: bytes                # the business persona handle (opaque)
    entity_class: EntityClass
    region: str
    conformant: bool = False     # passed the non-harm conformance bar (attestor-signed; stub here)
    paid: bool = False           # membership/tithe active (money settled on the private branch)


def is_surfaceable(b: Organization) -> bool:
    """The ACCESS GATE: a business's listings are eligible to be surfaced only if it has PAID
    (membership active) AND passed conformance. Eligibility only — this never affects rank."""
    return b.paid and b.conformant


def _tokens(s: str) -> set:
    return {t for t in s.lower().replace(",", " ").split() if t}


@dataclass
class Listing:
    business: bytes              # the business handle this listing belongs to
    public: HybridSigPublic      # the business's public key (proves it controls the handle)
    title: str
    tags: List[str]
    price_atlas: int
    region: str
    sig: bytes = b""

    def body(self) -> bytes:
        return H(b"atlas/listing", self.business, self.title.encode(),
                 " ".join(self.tags).encode(), str(self.price_atlas).encode(), self.region.encode())

    def id(self) -> bytes:
        return H(b"atlas/listing/id", self.body())


def list_item(identity: Child, title: str, tags: List[str], price_atlas: int, region: str) -> Listing:
    """A business publishes a signed product listing for its own handle."""
    lst = Listing(business=identity.handle, public=identity.public, title=title, tags=list(tags),
                  price_atlas=price_atlas, region=region)
    lst.sig = sign(identity.keypair, lst.body())
    return lst


def verify_listing(lst: Listing) -> bool:
    """Valid iff the listing's business handle IS the handle of its public key and the signature
    is by that key — a business can only list under a handle it controls."""
    if handle_of(lst.public.encode()) != lst.business:
        return False
    return verify(lst.public, lst.body(), lst.sig)


def surface(query: str, region: Optional[str], listings: Sequence[Listing],
            businesses: Sequence[Organization], review_net: Optional[Dict[bytes, int]] = None) -> List[Listing]:
    """The user's agent asks for what they NEED; return eligible, matching listings ranked by
    relevance + verified-human review score. Payment/standing only GATES eligibility — it never
    lifts rank — and only genuine matches are returned (pull, not push, no ads)."""
    review_net = review_net or {}
    biz = {b.handle: b for b in businesses}
    q = _tokens(query)
    scored = []
    for lst in listings:
        b = biz.get(lst.business)
        if b is None or not is_surfaceable(b):
            continue                                     # access gate: not paid/conformant -> ineligible
        if region is not None and lst.region != region:
            continue                                     # region-scoped
        if not verify_listing(lst):
            continue
        relevance = len(q & _tokens(lst.title + " " + " ".join(lst.tags)))
        if relevance == 0:
            continue                                     # no genuine match -> not surfaced (no push)
        scored.append((relevance, review_net.get(lst.id(), 0), lst))
    # rank by relevance, then verified-human reviews — NEVER by who paid
    scored.sort(key=lambda t: (t[0], t[1]), reverse=True)
    return [lst for _, _, lst in scored]
