"""Public web gateway — discoverable on the NORMAL web, no compromise.

A public persona gets a front door on the ordinary web that hands off into the app, without weakening
any Atlas guarantee. Two pieces:

  did:web MIRROR. A did:web view of the persona's key, served READ-ONLY as static JSON at
  https://<domain>/.well-known/did.json. It carries the SAME verification methods as the persona's
  did:atlas doc (same key) plus an `alsoKnownAs` back to did:atlas — so a web verifier fetching it by
  URL gets the exact key that IS the Atlas handle. Provable web<->atlas binding via the signed
  NameClaim (names.py): the name resolves to the handle, and the handle is the key's handle.

  SIGNED PUBLIC PAGE. A static, self-contained mirror of ONLY the persona's opted-in public profile +
  published works, SIGNED by the persona's key — so authenticity travels onto the untrusted web
  INDEPENDENT of TLS (a web-PKI MITM can degrade availability but cannot forge the persona's page).
  It carries an "Open in Atlas" universal link that resolves name -> handle -> the public space
  INSIDE the app, where full guarantees resume.

NO-COMPROMISE INVARIANTS (enforced here): only PUBLIC-persona data ever leaves (private personas have
no page — GatewayError); only THIS persona's works; the page/handle/name are all bound to one key; the
page is a read-only signed signpost, so the web cannot escalate into Atlas.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from ..crypto.primitives import H
from ..crypto.sign import HybridSigKeypair, HybridSigPublic, sign, verify
from ..keys.identity import handle_of
from ..names import NameClaim, verify_claim
from ..participant import Profile, Visibility
from .did import did_document, did_for

UNIVERSAL_LINK_BASE = "https://atlas.id/"       # the app claims this domain; mirrors atlas://<name>


class GatewayError(Exception):
    ...


def did_web_id(domain: str) -> str:
    """did:web method id — path segments become ':' per the spec; a bare domain is did:web:<domain>."""
    return "did:web:" + domain.strip("/").replace("/", ":")


def did_web_document(pub: HybridSigPublic, domain: str) -> dict:
    """A did:web DID document for the persona's key, served at https://<domain>/.well-known/did.json.
    Same verification methods as the did:atlas doc; alsoKnownAs bridges to did:atlas."""
    atlas = did_document(pub)
    web = did_web_id(domain)
    old = atlas["id"]

    def remap(s: str) -> str:
        if s == old:
            return web
        return web + s[len(old):] if s.startswith(old + "#") else s

    return {
        "@context": atlas["@context"],
        "id": web,
        "alsoKnownAs": [old],                    # provable link to the did:atlas identifier (same key)
        "verificationMethod": [{**vm, "id": remap(vm["id"]), "controller": web}
                               for vm in atlas["verificationMethod"]],
        "assertionMethod": [remap(x) for x in atlas["assertionMethod"]],
        "authentication": [remap(x) for x in atlas["authentication"]],
    }


def open_in_atlas(name: str) -> str:
    """The universal link a browser follows to hand off into the app's public space for `name`."""
    return UNIVERSAL_LINK_BASE + name


def parse_universal_link(url: str) -> Optional[str]:
    """Extract the persona name from an Open-in-Atlas link (the app then resolves name->handle->space
    via the NameRegistry). None if it isn't one of ours."""
    if url.startswith(UNIVERSAL_LINK_BASE):
        return url[len(UNIVERSAL_LINK_BASE):].strip("/") or None
    if url.startswith("atlas://"):
        return url[len("atlas://"):].strip("/") or None
    return None


@dataclass
class PublicPage:
    """The static, signed public mirror the web serves. Read-only data; no code, no trackers."""
    name: str
    handle: bytes
    public: HybridSigPublic
    domain: str
    display_name: str
    bio: str
    links: Tuple[str, ...]
    works: Tuple[dict, ...]          # citeable published works of THIS persona: {id,title,license}
    open_in_atlas: str
    sig: bytes = b""

    def body(self) -> bytes:
        payload = json.dumps({
            "name": self.name, "handle": self.handle.hex(), "domain": self.domain,
            "display_name": self.display_name, "bio": self.bio, "links": list(self.links),
            "works": [dict(w) for w in self.works], "open_in_atlas": self.open_in_atlas,
        }, sort_keys=True, separators=(",", ":")).encode()
        return H(b"atlas/web-page/v1", payload)


def build_public_page(*, profile: Profile, name_claim: NameClaim, signer: HybridSigKeypair,
                      domain: str, register) -> PublicPage:
    """Build the signed public mirror for a PUBLIC persona. Fails closed for a private persona, a
    signer that doesn't control the handle, or a name claim that doesn't bind to it. Includes only
    this persona's published works (gathered from the shared register by author handle)."""
    if profile.visibility is not Visibility.PUBLIC:
        raise GatewayError("only public personas have a web presence")
    if handle_of(signer.public.encode()) != profile.handle:
        raise GatewayError("signer does not control the profile handle")
    if name_claim.handle != profile.handle or not verify_claim(name_claim):
        raise GatewayError("name claim does not bind to this handle")
    handle_hex = profile.handle.hex()
    works = tuple({"id": it.id.hex(), "title": it.title, "license": it.license}
                  for it in register.search("") if it.author == handle_hex)
    page = PublicPage(name=name_claim.name, handle=profile.handle, public=signer.public, domain=domain,
                      display_name=profile.display_name, bio=profile.bio, links=tuple(profile.links),
                      works=works, open_in_atlas=open_in_atlas(name_claim.name))
    page.sig = sign(signer, page.body())
    return page


def verify_public_page(page: PublicPage, name_claim: NameClaim) -> bool:
    """A visitor's check — authenticity independent of TLS: the page is signed by the key, the key IS
    the handle, and the name claim binds the name to that handle."""
    return (verify(page.public, page.body(), page.sig)
            and handle_of(page.public.encode()) == page.handle
            and name_claim.handle == page.handle
            and name_claim.name == page.name
            and verify_claim(name_claim))
