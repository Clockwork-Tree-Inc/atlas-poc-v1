"""Persona login — a (username, password) account, BLINDLY stored server-side, whose real
cryptographic identity is a System-ID persona (`Profile`) that never surfaces.

This GENERALIZES the recovery anchor's (name, password) -> blind selector
(`realid/recovery_anchor`) from the single total-loss case to EVERYDAY persona login. Each
persona is a top-level compartment (`Profile`) that owns its own full stack — vault, messaging,
forum. The server storing a persona ever sees only:

  * the public `username` (a human label the person chose),
  * an opaque, blindly-derived SELECTOR (username + stretched password), and
  * the persona's public identity `handle`,

NEVER the System-ID, and never a link to the real you or to your OTHER personas. One persona may
additionally be CERTIFIED as the real, verified you (`realid/verification`); the rest stay
pseudonymous ("horseshit").

The password is a SELECTOR / login gate, NOT the source of the crypto identity — the identity is
the System-ID-derived `Profile` (so your card reconstitutes every persona on a new device). scrypt
(+ optional OPRF, exactly as recovery) resists offline enumeration of a leaked persona record.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Sequence

from ..crypto.primitives import H
from ..keys.identity import IdentityTree, Profile, PseudonymTier
from ..recovery import oprf

# Deployment-wide selector salt (a domain constant — the user carries nothing but username+password).
# Enumeration resistance comes from scrypt work + optional OPRF + server rate-limiting, not salt secrecy.
PERSONA_SELECTOR_SALT = b"atlas/persona-selector/v1"

# scrypt work factors — mirror recovery_anchor (stands in for Argon2id; kept modest for the PoC).
_SCRYPT_N = 1 << 14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_MAXMEM = 128 * _SCRYPT_R * _SCRYPT_N * 4


def _normalize_username(username: str) -> str:
    """Fold a username to a stable form (case/whitespace) so it addresses one record."""
    return " ".join(username.strip().lower().split())


def persona_selector(username: str, password: str, *,
                     salt: bytes = PERSONA_SELECTOR_SALT,
                     oprf_shards: Sequence[oprf.OPRFShard] | None = None) -> bytes:
    """The BLIND server-side handle for a persona login. Same construction as the recovery
    selector: the username + scrypt-stretched password (optionally OPRF-hardened against the
    servers' key). INDEPENDENT of the System-ID, so the server storing it cannot link the persona
    to the real you or to any other persona; a leaked persona store cannot be ground offline
    (scrypt cost + optional OPRF). The password differentiates you from namesakes; it is not the
    crypto identity."""
    name = _normalize_username(username)
    stretched = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                               n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32,
                               maxmem=_SCRYPT_MAXMEM)
    if oprf_shards is not None:
        stretched = oprf.evaluate_oblivious(oprf_shards, stretched)
    return H(b"atlas/persona-selector", name.encode("utf-8"), stretched)


@dataclass(frozen=True)
class Persona:
    """A persona a user operates as: the public `username`, its System-ID-derived `profile`
    (crypto identity + per-feature slices), and the blind `selector` the server keys on.
    `profile.handle` is what surfaces publicly; the System-ID never does."""

    username: str
    profile: Profile
    selector: bytes

    @property
    def handle(self) -> bytes:
        """The persona's public, opaque standing handle (what a relay / forum sees)."""
        return self.profile.handle

    def feature_handle(self, feature: str) -> bytes:
        """Opaque handle for one of this persona's surfaces ('messaging' / 'vault' / 'forum')."""
        return self.profile.feature(feature).handle


def open_persona(tree: IdentityTree, username: str, password: str, *,
                 tier: PseudonymTier = PseudonymTier.ANONYMOUS,
                 salt: bytes = PERSONA_SELECTOR_SALT,
                 oprf_shards: Sequence[oprf.OPRFShard] | None = None) -> Persona:
    """Open (derive) a persona for `username` under this identity tree: its blind login selector
    plus its System-ID persona (`Profile`). DETERMINISTIC — the same (tree, username, password,
    tier) always reopens the SAME persona, on any device, with nothing persisted. Use tier=PUBLIC
    for a persona you intend to certify as the real, verified you; ANONYMOUS for a pseudonym."""
    profile = tree.profile(username, tier=tier)
    selector = persona_selector(username, password, salt=salt, oprf_shards=oprf_shards)
    return Persona(username=username, profile=profile, selector=selector)
