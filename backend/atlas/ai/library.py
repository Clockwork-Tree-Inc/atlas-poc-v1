"""Federated library — a pluggable registry of LibrarySources feeding the librarian.

Every device is an author's shelf; outside libraries plug in as adapters — the user's on-device
vault, the public register, and external catalogs (a music-rights layer like auracles, a legal
library, a standards body). The registry queries them all, tags every result with WHICH source
surfaced it (provenance), and hands one merged corpus to the librarian's retrieve/cite engine so
ranking is global and consistent across sources.

Two guarantees this layer adds on top of the librarian:

  LICENSE-BY-DEFAULT (fail-safe). Any item that arrives from an adapter without an explicit license
  is stamped ALL_RIGHTS_RESERVED before it can be retrieved — never open by omission. A reserved
  work is not usable verbatim even at price 0 (see librarian.is_open); it is surfaced for a
  license/ask, not fed to the model. So a sloppy or hostile adapter cannot launder someone's work
  into "free".

  PROVENANCE. Each hit carries the name of the source that surfaced it, so the UI can show where a
  work came from and route a purchase/license request to the right rights-holder.

Pull-only, like the librarian and marketplace: sources are searched, never pushed. Adapters may push
the query down to their own catalog or return candidates; the registry license-normalizes + ranks
centrally either way. Reference-of-record (Python); the phone/node/server tiers all reuse it.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Dict, Iterable, List, Optional, Protocol, Tuple

from .librarian import (
    ALL_RIGHTS_RESERVED,
    CorpusItem,
    LibrarianHit,
    LibrarianResult,
    Model,
    librarian,
    retrieve,
)


class LibrarySource(Protocol):
    """A pluggable library. `name` is the provenance tag attached to everything it surfaces;
    `search` returns its authored/licensed candidate works for a query (pull-only). An external
    adapter (auracles / legal / standards) implements the same two members over its own catalog."""

    name: str

    def search(self, query: str, *, region: Optional[str] = None,
               top_k: int = 20) -> Iterable[CorpusItem]: ...


@dataclass
class InMemorySource:
    """A LibrarySource backed by a fixed list — the on-device vault shelf, or a stub standing in for
    an external adapter in tests. Real adapters implement the same interface over their catalog."""
    name: str
    items: List[CorpusItem] = field(default_factory=list)

    def search(self, query: str, *, region: Optional[str] = None,
               top_k: int = 20) -> Iterable[CorpusItem]:
        # Pull-only; the registry ranks + license-normalizes centrally, so a simple source just
        # offers its shelf and lets retrieve() do relevance.
        return list(self.items)


def normalize_license(item: CorpusItem) -> CorpusItem:
    """License-by-default: an item with a blank/unknown license is stamped ALL_RIGHTS_RESERVED
    (fail-safe restrictive) so it can never be treated as free by omission. An explicit license is
    lower-cased and kept as-is."""
    lic = (item.license or "").strip().lower()
    if lic in ("", "unknown"):
        return replace(item, license=ALL_RIGHTS_RESERVED)
    return replace(item, license=lic)


@dataclass(frozen=True)
class SourcedHit:
    """A librarian hit plus the provenance of the source that surfaced it."""
    hit: LibrarianHit
    source: str


@dataclass
class LibraryRegistry:
    """The set of plugged-in libraries. Query them all, license-normalize + dedup, and rank
    globally through the librarian's retrieve()."""
    _sources: List[LibrarySource] = field(default_factory=list)

    def register(self, source: LibrarySource) -> None:
        self._sources.append(source)

    @property
    def sources(self) -> Tuple[str, ...]:
        return tuple(s.name for s in self._sources)

    def gather(self, query: str, *, region: Optional[str] = None,
               top_k: int = 20) -> Tuple[List[CorpusItem], Dict[bytes, str]]:
        """Collect license-normalized candidates from every source into one corpus, remembering
        which source surfaced each id. First source to surface an id wins (stable, order-of-
        registration) so a later source can't silently override another's provenance/license."""
        merged: Dict[bytes, CorpusItem] = {}
        origin: Dict[bytes, str] = {}
        for s in self._sources:
            for raw in s.search(query, region=region, top_k=top_k):
                item = normalize_license(raw)
                if item.id not in merged:
                    merged[item.id] = item
                    origin[item.id] = s.name
        return list(merged.values()), origin

    def search(self, query: str, *, region: Optional[str] = None, top_k: int = 10,
               licensed_ids: Optional[set] = None) -> List[SourcedHit]:
        """Ranked hits across all plugged-in libraries, each tagged with its source."""
        corpus, origin = self.gather(query, region=region, top_k=top_k)
        hits = retrieve(query, corpus, licensed_ids=licensed_ids, region=region, top_k=top_k)
        return [SourcedHit(hit=h, source=origin.get(h.item, "?")) for h in hits]

    def answer(self, query: str, model: Model, *, region: Optional[str] = None, top_k: int = 10,
               licensed_ids: Optional[set] = None) -> LibrarianResult:
        """The full librarian answer over the federated corpus: retrieve across all sources →
        surface (cite + preview + buy) → summarise quoting ONLY the licensed subset. Reserved /
        unlicensed works are never fed to the model."""
        corpus, _origin = self.gather(query, region=region, top_k=top_k)
        return librarian(query, corpus, model, region=region, top_k=top_k, licensed_ids=licensed_ids)
