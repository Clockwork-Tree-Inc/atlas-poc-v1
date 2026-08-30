"""Publish — copy a work from a persona's private shelf into the ONE global library.

Publishing is NOT a destructive move: the content bytes stay in the persona's own vault/node; the
global register receives a citeable ENTRY (the CorpusItem: id, author, title, tags, license, price)
signed by the persona's key. So the register is a discovery + license layer, not a content store.

Three properties hold:
  * AUTHOR-CHOSEN LICENSE — the publisher sets the license at publish time (license-by-default: if
    left unset it stays all-rights-reserved, so the work is discoverable but surfaced as "ask", never
    accidentally free).
  * PROVENANCE + UNLINKABILITY — the entry is attributed to the persona HANDLE and signed by the
    persona's key; the register verifies the signature AND that the handle really is that key's handle,
    so only the controller of a handle can publish under it. The System-ID and other personas never
    appear — two personas of one human publish into the same global library, unlinkable.
  * ONE GLOBAL LIBRARY — FederatedRegister is the single shared commons every persona's registry reads
    (as a LibrarySource); publishing adds to it, unpublish (publisher-signed) removes.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from typing import Dict, List, Optional, Sequence

from ..crypto.primitives import H
from ..crypto.sign import HybridSigKeypair, HybridSigPublic, sign, verify
from ..keys.identity import handle_of
from ..session.vault import Vault
from .librarian import CorpusItem
from .vault_library import shelf

_ENTRY = b"atlas/publish/v1"
_UNPUB = b"atlas/unpublish/v1"


class PublishError(Exception):
    ...


def _entry_body(item: CorpusItem) -> bytes:
    payload = json.dumps({"id": item.id.hex(), "author": item.author, "title": item.title,
                          "tags": list(item.tags), "license": item.license,
                          "price_atlas": item.price_atlas, "region": item.region,
                          "origin": item.origin}, sort_keys=True, separators=(",", ":")).encode()
    return H(_ENTRY, payload)


@dataclass(frozen=True)
class RegisterEntry:
    """A signed, citeable pointer in the global library. No content bytes — those stay on the
    author's node."""
    item: CorpusItem                 # author = persona handle (hex), origin = "published"
    public: HybridSigPublic          # the publishing persona's key
    sig: bytes                       # persona's signature over the entry body


def make_entry(item: CorpusItem, signer: HybridSigKeypair) -> RegisterEntry:
    return RegisterEntry(item=item, public=signer.public,
                         sig=sign(signer, _entry_body(item)))


def sign_unpublish(signer: HybridSigKeypair, item_id: bytes) -> bytes:
    return sign(signer, H(_UNPUB, item_id))


@dataclass
class FederatedRegister:
    """The ONE global library. A LibrarySource every persona's registry reads; personas publish
    citeable entries under their own handle."""
    name: str = "register"
    _entries: Dict[bytes, RegisterEntry] = field(default_factory=dict)

    def publish(self, entry: RegisterEntry) -> None:
        if not verify(entry.public, _entry_body(entry.item), entry.sig):
            raise PublishError("bad publish signature")
        if handle_of(entry.public.encode()).hex() != entry.item.author:
            raise PublishError("author handle does not match the signing key")   # can't publish as someone else
        self._entries[entry.item.id] = entry

    def unpublish(self, item_id: bytes, sig: bytes) -> None:
        entry = self._entries.get(item_id)
        if entry is None:
            return
        if not verify(entry.public, H(_UNPUB, item_id), sig):
            raise PublishError("only the publisher can unpublish")
        del self._entries[item_id]

    def search(self, query: str, *, region: Optional[str] = None,
               top_k: int = 20) -> List[CorpusItem]:
        return [e.item for e in self._entries.values()]


def publish_from_vault(vault: Vault, register: FederatedRegister, *, item_id: bytes,
                       signer: HybridSigKeypair, license: Optional[str] = None,
                       price_atlas: Optional[int] = None) -> RegisterEntry:
    """Publish one of this persona's shelf items into the global library, under the persona's handle.
    The content bytes stay in the vault; only the citeable, signed entry goes to the register. The
    author-chosen `license` overrides the shelf item's (unset → the shelf item's license as-is)."""
    matches = [x for x in shelf(vault) if x.id == item_id]
    if not matches:
        raise PublishError("no such shelf item")
    src = matches[0]
    author = handle_of(signer.public.encode()).hex()
    lic = (license if license is not None else src.license).strip().lower()
    price = price_atlas if price_atlas is not None else src.price_atlas
    published = replace(src, author=author, license=lic, price_atlas=price, origin="published")
    entry = make_entry(published, signer)
    register.publish(entry)
    return entry
