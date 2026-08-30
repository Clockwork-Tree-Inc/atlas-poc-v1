"""Addressing + nameplate resolver — how a persona is FOUND, kept separate from how it's REACHED.

An address is `local@place` (ada@example.town, ada@example.id). The `@place` half says where to
fetch a signed NAMEPLATE; the `local` part selects which one. A nameplate carries the persona's key, a
display name, a way-to-knock (its receptive mode), and optionally its self-published trust bundle. It
does NOT carry a mailbox — discovery is stable and public; delivery rotates and stays private (see
net/privacy/mailbox and the rotating connect code). Because the nameplate is signed by the persona key,
the host is untrusted: self-host it, mirror it, or serve it from your own node, it verifies the same.

Two independent switches per persona:
  * FINDABLE — is there a published nameplate at all / are you discoverable. Off = no nameplate.
  * RECEPTIVE — can someone open a channel, and on what terms: OPEN / CODE_ONLY / CONTACTS_ONLY / CLOSED.
Findable does not imply receptive: you can be loudly discoverable with a closed door, or unlisted yet
reachable by anyone holding your code.

Many addresses can point at one persona, and one persona's mail can converge into your real inbox — but
that mapping is a PRIVATE, owner-held RoutingTable, never published, so senders learn only the persona
face they were given. Swift parity in Address.swift.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Dict, Optional

from ..crypto.primitives import H
from ..crypto.sign import HybridSigKeypair, HybridSigPublic, sign, verify
from .trust_publish import TrustBundle, parse_trust_bundle


class AddressError(Exception):
    ...


class ReceptiveMode(Enum):
    OPEN = "open"                    # anyone may open a channel
    CODE_ONLY = "code-only"          # only with a valid connect code (see the rotating connect code)
    CONTACTS_ONLY = "contacts-only"  # only already-accepted contacts
    CLOSED = "closed"                # not reachable; discovery only


@dataclass(frozen=True)
class Address:
    local: str
    place: str

    def __str__(self) -> str:
        return f"{self.local}@{self.place}"


def parse_address(s: str) -> Address:
    s = s.strip()
    if s.count("@") != 1:
        raise AddressError("an address is exactly local@place")
    local, place = s.split("@")
    if not local or not place:
        raise AddressError("both local and place are required")
    return Address(local=local, place=place.strip("/").lower())


def nameplate_url(addr: Address) -> str:
    """Where the place serves this local's nameplate — one host serves many locals, like email."""
    return f"https://{addr.place}/.well-known/atlas/{addr.local}.json"


@dataclass
class DiscoverySettings:
    """A persona's two independent switches."""
    findable: bool = False
    receptive: ReceptiveMode = ReceptiveMode.CLOSED

    def accepts_contact(self, *, has_valid_code: bool, is_known_contact: bool) -> bool:
        if self.receptive is ReceptiveMode.OPEN:
            return True
        if self.receptive is ReceptiveMode.CODE_ONLY:
            return has_valid_code
        if self.receptive is ReceptiveMode.CONTACTS_ONLY:
            return is_known_contact
        return False


@dataclass
class Nameplate:
    """The signed discovery record served at nameplate_url. Signed by the persona key; the host is
    untrusted. Carries the receptive mode (a way to knock), never a mailbox."""
    local: str
    place: str
    key: HybridSigPublic
    display_name: str
    receptive: ReceptiveMode
    trust_bundle: Optional[TrustBundle] = None
    sig: bytes = b""

    def body(self) -> bytes:
        def lp(b: bytes) -> bytes:
            return len(b).to_bytes(4, "big") + b
        bundle_tag = self.trust_bundle.body() if self.trust_bundle is not None else b""
        return H(b"atlas/nameplate/v1", lp(self.local.encode()), lp(self.place.encode()),
                 lp(self.key.encode()), lp(self.display_name.encode()),
                 lp(self.receptive.value.encode()), lp(bundle_tag))

    def to_json(self) -> bytes:
        obj = {"local": self.local, "place": self.place, "key": self.key.encode().hex(),
               "display_name": self.display_name, "receptive": self.receptive.value,
               "sig": self.sig.hex()}
        if self.trust_bundle is not None:
            obj["trust_bundle"] = json.loads(self.trust_bundle.to_json().decode())
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def build_nameplate(persona: HybridSigKeypair, *, address: Address, display_name: str,
                    settings: DiscoverySettings, trust_bundle: Optional[TrustBundle] = None
                    ) -> Optional[Nameplate]:
    """Publish a nameplate for a FINDABLE persona (None if it isn't findable — nothing to serve)."""
    if not settings.findable:
        return None
    np = Nameplate(local=address.local, place=address.place, key=persona.public,
                   display_name=display_name, receptive=settings.receptive, trust_bundle=trust_bundle)
    np.sig = sign(persona, np.body())
    return np


def verify_nameplate(np: Nameplate) -> bool:
    """The nameplate is signed by the very key it advertises (so the place can't forge it)."""
    return verify(np.key, np.body(), np.sig)


def parse_nameplate(data: bytes) -> Nameplate:
    d = json.loads(data)
    bundle = None
    if "trust_bundle" in d:
        bundle = parse_trust_bundle(json.dumps(d["trust_bundle"]).encode())
    return Nameplate(local=d["local"], place=d["place"],
                     key=HybridSigPublic.decode(bytes.fromhex(d["key"])),
                     display_name=d["display_name"], receptive=ReceptiveMode(d["receptive"]),
                     trust_bundle=bundle, sig=bytes.fromhex(d["sig"]))


def resolve(address_str: str, *, fetch: Callable[[str], bytes]) -> Nameplate:
    """Look up an address: fetch its nameplate, verify the signature, return it. `fetch` is injected
    (real HTTP in the app/node, a stub in tests). Raises AddressError if the signature doesn't check."""
    addr = parse_address(address_str)
    np = parse_nameplate(fetch(nameplate_url(addr)))
    if np.local != addr.local or np.place != addr.place or not verify_nameplate(np):
        raise AddressError("nameplate failed verification or does not match the address")
    return np


class RoutingTable:
    """The owner's PRIVATE map: which persona an address points at, and which real inbox a persona
    converges into. Never published — senders only ever see the persona face they were handed, so
    convergence into one inbox stays invisible to them."""

    def __init__(self) -> None:
        self._addr_to_persona: Dict[str, bytes] = {}      # address string -> persona key enc
        self._persona_to_inbox: Dict[bytes, bytes] = {}   # persona key enc -> private inbox id

    def point(self, address_str: str, persona: HybridSigPublic) -> None:
        self._addr_to_persona[address_str] = persona.encode()

    def converge(self, persona: HybridSigPublic, inbox_id: bytes) -> None:
        self._persona_to_inbox[persona.encode()] = inbox_id

    def persona_for(self, address_str: str) -> Optional[bytes]:
        return self._addr_to_persona.get(address_str)

    def inbox_for(self, persona: HybridSigPublic) -> Optional[bytes]:
        return self._persona_to_inbox.get(persona.encode())

    def inbox_for_address(self, address_str: str) -> Optional[bytes]:
        """The full private hop a sender never sees: address -> persona -> your real inbox."""
        pk = self._addr_to_persona.get(address_str)
        return self._persona_to_inbox.get(pk) if pk is not None else None
