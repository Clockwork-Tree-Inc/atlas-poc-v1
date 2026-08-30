"""The per-persona vault library — a persona's OWN isolated shelf as a LibrarySource, plus import.

Each persona owns its own `Vault` (its own 32-byte storage key, independent of the System-ID), so a
persona's library is a cryptographically SEPARATE space — not rows in a shared store filtered by a
persona tag. `VaultLibrarySource` exposes that persona's shelf to the librarian/registry; `import_bytes`
brings outside device content INTO the active persona's vault.

Import is fail-safe by construction:
  * the content bytes are SEALED into the persona's own vault (encrypted at rest, isolated);
  * provenance is honestly marked `origin="imported"` — an imported file was NOT captured live in
    Atlas, so it never masquerades as Atlas-captured;
  * the license defaults to ALL_RIGHTS_RESERVED — you may not hold rights to arbitrary device content,
    so an import is never usable/publishable-as-yours until you attach a license you're entitled to.

Composed per the two-layer model: instantiate a fresh registry per active persona with THIS persona's
VaultLibrarySource as its private source, plus the single global register as the shared read source.
"""
from __future__ import annotations

import json
from typing import List, Optional, Sequence

from ..session.vault import Vault
from .librarian import ALL_RIGHTS_RESERVED, CorpusItem

SHELF_KEY = "__atlas.library.shelf.v1__"          # the persona's shelf index, sealed in its vault
_CONTENT_PREFIX = "__atlas.library.content__/"    # sealed content bytes, keyed by item id


def _to_dict(it: CorpusItem) -> dict:
    return {"id": it.id.hex(), "author": it.author, "title": it.title, "tags": list(it.tags),
            "license": it.license, "price_atlas": it.price_atlas, "region": it.region,
            "origin": it.origin}


def _from_dict(d: dict) -> CorpusItem:
    return CorpusItem(id=bytes.fromhex(d["id"]), author=d["author"], title=d["title"],
                      tags=tuple(d["tags"]), license=d["license"], price_atlas=d["price_atlas"],
                      region=d.get("region", ""), origin=d.get("origin", ""))


def shelf(vault: Vault) -> List[CorpusItem]:
    """The persona's shelf (its library index), decrypted from its own vault. Empty if none yet."""
    if SHELF_KEY not in vault:
        return []
    return [_from_dict(d) for d in json.loads(vault.get(SHELF_KEY).decode())]


def _write_shelf(vault: Vault, items: Sequence[CorpusItem]) -> None:
    vault.put(SHELF_KEY, json.dumps([_to_dict(x) for x in items]).encode())


def import_bytes(vault: Vault, *, id: bytes, author: str, title: str,
                 content: bytes, tags: Sequence[str] = (),
                 license: str = ALL_RIGHTS_RESERVED, origin: str = "imported",
                 price_atlas: int = 0, region: str = "") -> CorpusItem:
    """Bring outside content INTO this persona's vault: seal the bytes, add a shelf entry. Defaults
    are fail-safe (reserved license, imported provenance). Re-importing the same id replaces it."""
    vault.put(_CONTENT_PREFIX + id.hex(), content)          # sealed into the persona's own space
    item = CorpusItem(id=id, author=author, title=title, tags=tuple(tags), license=license,
                      price_atlas=price_atlas, region=region, origin=origin)
    items = [x for x in shelf(vault) if x.id != id] + [item]
    _write_shelf(vault, items)
    return item


def read_content(vault: Vault, item: CorpusItem) -> bytes:
    """The sealed bytes for a shelf item, decrypted on demand from the persona's own vault."""
    return vault.get(_CONTENT_PREFIX + item.id.hex())


class VaultLibrarySource:
    """A LibrarySource backed by ONE persona's vault shelf. Isolation is inherent: it can only read
    the vault it was handed (that persona's own keyed container), so no cross-persona bleed is
    possible. Pull-only; the registry license-normalizes + ranks centrally."""

    def __init__(self, name: str, vault: Vault) -> None:
        self.name = name
        self._vault = vault

    def search(self, query: str, *, region: Optional[str] = None,
               top_k: int = 20) -> List[CorpusItem]:
        return shelf(self._vault)
