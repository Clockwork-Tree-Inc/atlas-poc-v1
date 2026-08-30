"""The librarian: retrieval + citation over authored, provenanced, licensed works.

Atlas AI is a LIBRARIAN, not a ghostwriter (see DESIGN_DECISIONS / ai-integration-model):
it SURFACES known authored things, CITES them exactly, and routes you to PURCHASE the real
work from its author. It never launders authored work into an opaque generated answer.

This module is the retriever the `seam` was missing (`web_search` was the only source builder).
The SAME engine runs at every tier, over the RIGHT corpus for that tier:
  * PHONE  — the user's on-device personal AI, over their private vault.
  * NODE   — the user's OWN computer-grade private AI (local to the user, theirs), over their
             private corpus; can escalate to the commons.
  * SERVER — the COMMONS ("no-one's / everyone's"): the training-weights commons (the community
             model tree) + the PUBLIC REGISTER for public/marketplace authored works. This is the
             corpus the librarian searches for shared/public discovery.

Two-lane licensing (author is sovereign per work):
  * OPEN lane   — AGPL (code) / Creative Commons (content) / price 0 → always usable, free, but
                  STILL attributed. `license_ok=True`, no purchase needed.
  * CONTENT lane— an explicit paid license with a scope → usable (quotable verbatim) only if the
                  holder bought it; otherwise surfaced for PREVIEW + a purchase pointer.

The generated summary (via the open, ethically-sourced model behind the seam) quotes ONLY the
licensed subset; unlicensed hits are surfaced as "buy to unlock", never fed to the model.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Set, Tuple

from .seam import InferenceResult, Model, Source, run_inference

# Licenses that make a work OPEN — usable freely (still attributed), no purchase.
OPEN_LICENSES = {
    "agpl", "agpl-3.0", "cc-by", "cc-by-sa", "cc0", "public-domain", "open",
}

# The fail-safe default license: a work whose license is unknown/absent is ALL RIGHTS RESERVED —
# not open, and NOT usable even at price 0 ("not for sale" is the most restrictive state, not the
# freest). License-by-default (see atlas/ai/library.py) stamps this so a plugged-in library can
# never make a work accidentally free by omitting its license.
ALL_RIGHTS_RESERVED = "all-rights-reserved"
RESERVED_LICENSES = {ALL_RIGHTS_RESERVED, "unknown", ""}


def is_open(license: str, price_atlas: int) -> bool:
    """A work is OPEN (free to use, still cited) if its license is a copyleft/CC/open one OR it
    carries no price. Everything else is a paid content license — usable only once bought. EXCEPT:
    an explicitly reserved/unknown license is never auto-open, even at price 0 — that is the fail-
    safe, so a missing license reads as 'ask/buy', never as 'free'."""
    lic = (license or "").strip().lower()
    if lic in RESERVED_LICENSES:
        return False
    return price_atlas <= 0 or lic in OPEN_LICENSES


@dataclass(frozen=True)
class CorpusItem:
    """One authored, provenanced work in the retrievable corpus. `license` + `price_atlas` decide
    the lane; `author` is the handle credited (and paid on sale)."""
    id: bytes
    author: str
    title: str
    tags: Tuple[str, ...]
    license: str = "open"
    price_atlas: int = 0
    region: str = ""
    origin: str = ""            # provenance class: "" / "atlas-captured" / "imported" / "published"


@dataclass(frozen=True)
class LibrarianHit:
    """A ranked, surfaced result — carries everything the UI needs to cite, preview, and offer a
    purchase, plus whether the holder may already quote it verbatim (`licensed`)."""
    item: bytes
    author: str
    title: str
    license: str
    price_atlas: int
    licensed: bool       # holder may use/quote verbatim (open, or already bought)
    score: int           # relevance (higher = better)

    @property
    def purchasable(self) -> bool:
        """Surfaced but not yet usable → show a buy pointer."""
        return not self.licensed and self.price_atlas > 0

    def as_source(self) -> Source:
        return Source(item=self.item, author=self.author, license_ok=self.licensed)


@dataclass(frozen=True)
class LibrarianResult:
    query: str
    hits: Tuple[LibrarianHit, ...]              # ALL relevant works (surfaced: cite + preview + buy)
    inference: Optional[InferenceResult]        # summary quoting ONLY the licensed subset (or None)

    @property
    def to_buy(self) -> Tuple[LibrarianHit, ...]:
        """Relevant works the holder must purchase to unlock verbatim use."""
        return tuple(h for h in self.hits if h.purchasable)

    @property
    def cited(self) -> Tuple[LibrarianHit, ...]:
        """Works the holder already holds a license for (used in the summary)."""
        return tuple(h for h in self.hits if h.licensed)


def _tokens(text: str) -> Set[str]:
    """Lowercased word set — mirrors marketplace surfacing so ranking is consistent."""
    return {w for w in "".join(c.lower() if c.isalnum() else " " for c in text).split() if w}


def retrieve(query: str, corpus: Iterable[CorpusItem], *,
             licensed_ids: Optional[Set[bytes]] = None,
             region: Optional[str] = None, top_k: int = 10) -> List[LibrarianHit]:
    """Rank corpus items by relevance to `query` (token overlap on title + tags), region-scoped
    if asked, and mark each as licensed (open, or the holder bought it). Only genuine matches are
    returned — no push, pull only (matches marketplace `surface`). Highest relevance first."""
    held = licensed_ids or set()
    q = _tokens(query)
    hits: List[LibrarianHit] = []
    for it in corpus:
        if region is not None and it.region and it.region != region:
            continue
        overlap = len(q & (_tokens(it.title) | {t.lower() for t in it.tags}))
        if overlap == 0:
            continue
        licensed = is_open(it.license, it.price_atlas) or it.id in held
        hits.append(LibrarianHit(item=it.id, author=it.author, title=it.title,
                                 license=it.license, price_atlas=it.price_atlas,
                                 licensed=licensed, score=overlap))
    # relevance first, then already-licensed ahead of buy-to-unlock, then cheaper first
    hits.sort(key=lambda h: (h.score, h.licensed, -h.price_atlas), reverse=True)
    return hits[:top_k]


def librarian(query: str, corpus: Iterable[CorpusItem], model: Model, *,
              licensed_ids: Optional[Set[bytes]] = None,
              region: Optional[str] = None, top_k: int = 10) -> LibrarianResult:
    """The full librarian answer: retrieve → surface all relevant works (cite + preview + buy) →
    generate a grounded summary that quotes ONLY the licensed subset. The model is admitted through
    the seam's open + ethically-sourced gate inside `run_inference`; unlicensed hits are NEVER fed
    to it (surfaced for purchase only)."""
    hits = retrieve(query, corpus, licensed_ids=licensed_ids, region=region, top_k=top_k)
    licensed_sources = [h.as_source() for h in hits if h.licensed]
    inference = run_inference(model, query, licensed_sources) if licensed_sources else None
    return LibrarianResult(query=query, hits=tuple(hits), inference=inference)
