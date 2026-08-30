"""Crypto-agility seam (TRUST_LAYER.md #10).

Generalizes the swappable `realid/credential_scheme.CredentialScheme` seam to ALL swappable
families — KEM, signature, credential — behind one registry + a versioned, committed suite. The
point: migrating a primitive (e.g. to a standardized PQ anon-credential) is a registry + suite-id
change, never a change at the call sites, and both peers/platforms agree on the ACTIVE suite by a
byte-exact `suite_id` so there is no ambiguity about which algorithms are in force.

  * `SchemeRegistry` — named scheme implementations per `SchemeFamily`, with a default per family.
  * `CryptoSuite` — a named, versioned bundle `(kem, signature, credential)` with a deterministic
    `suite_id()` commitment (parity-critical: every platform derives the same id).
  * `negotiate` — pick the strongest suite both sides support, in the local preference order,
    fail-closed if there is no overlap.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Dict, List, Optional, Sequence

from .primitives import H

_SUITE = b"atlas/crypto-suite"


class SchemeFamily(str, Enum):
    KEM = "kem"
    SIGNATURE = "signature"
    CREDENTIAL = "credential"


class AgilityError(Exception):
    pass


class UnknownScheme(AgilityError):
    pass


class NoCommonSuite(AgilityError):
    """The two parties share no supported suite — fail closed (never silently downgrade)."""


@dataclass(frozen=True)
class SchemeId:
    """A registered algorithm. `pq` marks it post-quantum (or a PQ-hybrid), so migration status
    is machine-readable."""

    family: SchemeFamily
    name: str
    pq: bool


class SchemeRegistry:
    """Named scheme implementations per family. Call sites resolve by (family, name); swapping an
    implementation is a `register` call, not a code change."""

    def __init__(self) -> None:
        self._impls: Dict[tuple[SchemeFamily, str], object] = {}
        self._ids: Dict[tuple[SchemeFamily, str], SchemeId] = {}
        self._default: Dict[SchemeFamily, str] = {}

    def register(self, scheme_id: SchemeId, impl: object, *, default: bool = False) -> None:
        key = (scheme_id.family, scheme_id.name)
        self._impls[key] = impl
        self._ids[key] = scheme_id
        if default or scheme_id.family not in self._default:
            self._default[scheme_id.family] = scheme_id.name

    def get(self, family: SchemeFamily, name: str) -> object:
        try:
            return self._impls[(family, name)]
        except KeyError:
            raise UnknownScheme(f"no {family.value} scheme named {name!r}")

    def scheme_id(self, family: SchemeFamily, name: str) -> SchemeId:
        try:
            return self._ids[(family, name)]
        except KeyError:
            raise UnknownScheme(f"no {family.value} scheme named {name!r}")

    def default(self, family: SchemeFamily) -> str:
        if family not in self._default:
            raise UnknownScheme(f"no default registered for {family.value}")
        return self._default[family]

    def available(self, family: SchemeFamily) -> List[SchemeId]:
        return [sid for (fam, _), sid in self._ids.items() if fam is family]


def _lp(s: str) -> bytes:
    b = s.encode("utf-8")
    return len(b).to_bytes(4, "big") + b


@dataclass(frozen=True)
class CryptoSuite:
    """A named, versioned bundle of the active schemes. Its `suite_id` is a byte-exact commitment
    both peers compute independently, so there is never ambiguity about the active algorithms."""

    version: int
    kem: str
    signature: str
    credential: str

    def suite_id(self) -> bytes:
        return H(_SUITE, self.version.to_bytes(4, "big"),
                 _lp(self.kem), _lp(self.signature), _lp(self.credential))

    def is_post_quantum(self, registry: SchemeRegistry) -> bool:
        """True iff EVERY family in the suite resolves to a PQ (or PQ-hybrid) scheme."""
        return (registry.scheme_id(SchemeFamily.KEM, self.kem).pq
                and registry.scheme_id(SchemeFamily.SIGNATURE, self.signature).pq
                and registry.scheme_id(SchemeFamily.CREDENTIAL, self.credential).pq)


def negotiate(preference: Sequence[CryptoSuite], remote_ids: set[bytes], *,
              acceptable: "Callable[[CryptoSuite], bool] | None" = None) -> CryptoSuite:
    """Pick the strongest suite both sides support: the FIRST suite in the local preference order
    (best first) whose `suite_id` the remote also supports AND that meets the `acceptable` floor.
    Fail-closed if there is no overlap, or none of the overlap meets the floor — never silently
    pick an unlisted or below-floor suite.

    A `acceptable` floor (e.g. PQ-only: ``lambda s: s.is_post_quantum(registry)``) means a MITM who
    strips the remote's advertised set down to only weak suites cannot force a downgrade — the
    result is a hard failure, not a weak agreement.

    SECURITY (for when this is wired): run negotiation INSIDE the identity-authenticated channel so
    `remote_ids` cannot be tampered, and BIND the agreed `suite_id` into the session-key derivation
    so both sides confirm the same suite (this is what actually defeats the FREAK/Logjam-class
    downgrade; the floor is defence-in-depth)."""
    for suite in preference:
        if suite.suite_id() in remote_ids and (acceptable is None or acceptable(suite)):
            return suite
    raise NoCommonSuite("no suite supported by both parties that meets the strength floor")
