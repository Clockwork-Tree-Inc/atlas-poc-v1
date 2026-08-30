"""Self-published accreditation — orgs publish their OWN trust edges at their OWN domain.

No central registry. An org (a university, an accreditor, a registry) serves a signed `TrustBundle` at
`https://<domain>/.well-known/atlas-trust.json`: the accreditations it HOLDS ("who accredited me") and
the ones it ISSUES ("who I accredit / authorize / certify"). Anyone fetches it, verifies it, and folds
the edges into their own `TrustGraph` — the same walkable graph, populated straight from the source.

Why this is safe without a gatekeeper: every edge is INDEPENDENTLY signature-checked (an org cannot
forge an accreditation it didn't receive — the accreditor's own signature would fail), and the bundle
signature binds the whole collection to the publishing key + domain. Combined with the did:web document
at the same domain (see web_gateway.did_web_document), a fetcher learns "this domain's key, and the
accreditations that key stands behind." Trust still binds where it always does: the CONSUMER decides
which roots it trusts when it walks the graph. This module only delivers the edges from the front door.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable, Iterable, Tuple

from ..crypto.primitives import H
from ..crypto.sign import HybridSigKeypair, HybridSigPublic, sign, verify
from ..issuers import credential_id
from ..participant import Attestation, verify_attestation
from ..trust_graph import TrustGraph

WELL_KNOWN_TRUST = "/.well-known/atlas-trust.json"


def _lp(b: bytes) -> bytes:
    """Length-prefix a variable field so the signed body is unambiguous (parity with Swift)."""
    return len(b).to_bytes(4, "big") + b


class TrustPublishError(Exception):
    ...


def edge_to_dict(a: Attestation) -> dict:
    """Serialize one signed edge to a JSON-safe dict (keys are hex; the signature travels with it)."""
    return {"authority_name": a.authority_name, "authority": a.authority.encode().hex(),
            "subject": a.subject.hex(), "claim": a.claim, "epoch": a.epoch, "sig": a.sig.hex()}


def edge_from_dict(d: dict) -> Attestation:
    return Attestation(authority_name=d["authority_name"],
                       authority=HybridSigPublic.decode(bytes.fromhex(d["authority"])),
                       subject=bytes.fromhex(d["subject"]), claim=d["claim"],
                       epoch=int(d["epoch"]), sig=bytes.fromhex(d["sig"]))


@dataclass
class TrustBundle:
    """The signed set of edges an org publishes about itself at its domain."""
    domain: str
    publisher: HybridSigPublic       # the org's key — trust binds here, the domain is provenance
    edges: Tuple[Attestation, ...]
    sig: bytes = b""

    def body(self) -> bytes:
        """The SIGNED body — length-prefixed field concatenation, independent of JSON formatting, so a
        bundle signed by the Swift app verifies on the Python backend and vice versa. Each edge is
        bound by its credential id (issuer+subject+claim+epoch); the edge signatures are checked
        separately at verify time."""
        parts = [b"atlas/trust-bundle/v1",
                 len(self.edges).to_bytes(4, "big"),
                 _lp(self.domain.encode()),
                 _lp(self.publisher.encode())]
        parts += [credential_id(e) for e in self.edges]
        return H(*parts)

    def to_json(self) -> bytes:
        """The static bytes served at the well-known URL (transport envelope; the signed body above is
        what authenticates, so key ordering here does not matter)."""
        return json.dumps({"domain": self.domain, "publisher": self.publisher.encode().hex(),
                           "edges": [edge_to_dict(e) for e in self.edges], "sig": self.sig.hex()},
                          sort_keys=True, separators=(",", ":")).encode()


def build_trust_bundle(*, publisher: HybridSigKeypair, domain: str,
                       edges: Iterable[Attestation]) -> TrustBundle:
    """Assemble + sign a bundle. Every edge must be validly signed and must INVOLVE the publisher
    (as subject or as authority) — an org publishes its own accreditations, not arbitrary ones."""
    edges = tuple(edges)
    pk = publisher.public.encode()
    for e in edges:
        if not verify_attestation(e):
            raise TrustPublishError("bundle contains an invalidly-signed edge")
        if e.subject != pk and e.authority.encode() != pk:
            raise TrustPublishError("bundle edge does not involve the publisher")
    b = TrustBundle(domain=domain, publisher=publisher.public, edges=edges)
    b.sig = sign(publisher, b.body())
    return b


def parse_trust_bundle(data: bytes) -> TrustBundle:
    d = json.loads(data)
    return TrustBundle(domain=d["domain"],
                       publisher=HybridSigPublic.decode(bytes.fromhex(d["publisher"])),
                       edges=tuple(edge_from_dict(x) for x in d["edges"]),
                       sig=bytes.fromhex(d["sig"]))


def verify_trust_bundle(b: TrustBundle) -> bool:
    """Publisher signature valid, and every edge validly signed AND about the publisher."""
    if not verify(b.publisher, b.body(), b.sig):
        return False
    pk = b.publisher.encode()
    return all(verify_attestation(e) and (e.subject == pk or e.authority.encode() == pk)
               for e in b.edges)


def trust_bundle_url(domain: str) -> str:
    return "https://" + domain.strip("/") + WELL_KNOWN_TRUST


def load_into(graph: TrustGraph, bundle: TrustBundle) -> int:
    """Verify a bundle and fold its edges into the graph. Returns the number of edges loaded."""
    if not verify_trust_bundle(bundle):
        raise TrustPublishError("bundle failed verification")
    for e in bundle.edges:
        graph.add(e)
    return len(bundle.edges)


def fetch_and_load(graph: TrustGraph, domain: str, *,
                   fetch: Callable[[str], bytes]) -> int:
    """Pull a domain's published bundle and fold it in. `fetch` is injected (real HTTP in the app/node,
    a stub in tests) so this stays dependency-free and testable."""
    return load_into(graph, parse_trust_bundle(fetch(trust_bundle_url(domain))))


def http_fetch(url: str, *, timeout: float = 10.0) -> bytes:
    """A tiny stdlib GET for real use — the app/node passes this as `fetch`."""
    import urllib.request
    with urllib.request.urlopen(url, timeout=timeout) as r:  # noqa: S310 — https URL built by us
        return r.read()
