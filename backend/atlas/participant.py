"""Participant & profile — everyone and everything is ONE participant class.

A participant is any typed entity (INDIVIDUAL / NONPROFIT / FOR_PROFIT) operating as a persona handle.
It has an OPT-IN public profile on the ANONYMOUS -> PUBLIC -> VERIFIED spectrum (self-service — anyone
makes their own), may HOLD attestations from credential authorities ("verified by X"), and — if it is
itself an authority — may ATTEST others.

Credential authorities (a medical board, a standards body, a government office, an age-verifier) are
NOT a privileged subsystem: they are just participants that issue signed attestations, discoverable and
reviewable like anyone. VERIFICATION, NOT AUTHORITY — Atlas anoints no root: an attestation is only as
good as the KEY that signed it, and a CONSUMER decides which authority keys it trusts. The authority's
NAME is a mere display label (anyone can call themselves anything); trust binds to the key.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Set, Tuple

from .crypto.primitives import H
from .crypto.sign import HybridSigKeypair, HybridSigPublic, sign, verify
from .marketplace import EntityClass


class Visibility(Enum):
    ANONYMOUS = "anonymous"      # no public profile — the default
    PUBLIC = "public"            # name + bio listed (VERIFIED is derived: public + >=1 valid attestation)


class ParticipantError(Exception):
    ...


@dataclass
class Attestation:
    """A signed claim by an AUTHORITY about a SUBJECT participant ("licensed-physician",
    "age-band:18+", "accredited-university"). Verified against the authority's KEY; the authority's
    NAME is only a label. The consumer decides whether it trusts that key."""
    authority_name: str
    authority: HybridSigPublic       # trust binds HERE, not to the name
    subject: bytes                   # the subject persona handle the claim is about
    claim: str
    epoch: int = 0
    sig: bytes = b""

    def body(self) -> bytes:
        return H(b"atlas/attestation/v1", self.authority_name.encode(), self.subject,
                 self.claim.encode(), str(self.epoch).encode())


def issue_attestation(authority_kp: HybridSigKeypair, *, authority_name: str, subject: bytes,
                      claim: str, epoch: int = 0) -> Attestation:
    """An authority (any participant) signs a claim about a subject handle."""
    a = Attestation(authority_name=authority_name, authority=authority_kp.public,
                    subject=subject, claim=claim, epoch=epoch)
    a.sig = sign(authority_kp, a.body())
    return a


def verify_attestation(a: Attestation) -> bool:
    """Valid iff the authority's signature over the claim body checks out. Says nothing about whether
    the authority is TRUSTWORTHY — that is the consumer's call (see `presents`)."""
    return verify(a.authority, a.body(), a.sig)


@dataclass
class Profile:
    """A participant's self-service profile. Anonymous by default; opt into public (name/bio/links);
    'verified' is DERIVED from holding valid authority attestations."""
    handle: bytes
    entity_class: EntityClass
    public: HybridSigPublic
    display_name: str = ""
    bio: str = ""
    links: Tuple[str, ...] = ()
    visibility: Visibility = Visibility.ANONYMOUS
    attestations: List[Attestation] = field(default_factory=list)
    achievements: Tuple[str, ...] = ()                 # soulbound kinds (the SBTs live in participation/soulbound)

    def go_public(self, *, display_name: str, bio: str = "", links: Tuple[str, ...] = ()) -> None:
        """Opt in to a public profile. Reversible (set back to anonymous by clearing)."""
        if not display_name:
            raise ParticipantError("a public profile needs a display name")
        self.visibility = Visibility.PUBLIC
        self.display_name = display_name
        self.bio = bio
        self.links = tuple(links)

    def go_anonymous(self) -> None:
        self.visibility = Visibility.ANONYMOUS
        self.display_name = self.bio = ""
        self.links = ()

    def hold(self, a: Attestation) -> None:
        """Accept an attestation ABOUT this participant. Rejects a forged one or one about someone
        else — you can't collect credentials that aren't yours or aren't real."""
        if a.subject != self.handle:
            raise ParticipantError("attestation is about a different subject")
        if not verify_attestation(a):
            raise ParticipantError("attestation signature invalid")
        self.attestations.append(a)

    def verified_by(self) -> Tuple[str, ...]:
        """Display: the authority NAMES that validly attest this participant (labels, not trust)."""
        return tuple(a.authority_name for a in self.attestations
                     if a.subject == self.handle and verify_attestation(a))

    @property
    def is_verified(self) -> bool:
        return self.visibility is Visibility.PUBLIC and len(self.verified_by()) > 0


def create_profile(*, handle: bytes, public: HybridSigPublic, entity_class: EntityClass) -> Profile:
    """Self-service: anyone makes their own profile for a persona handle they control (anonymous
    until they choose to go public)."""
    return Profile(handle=handle, entity_class=entity_class, public=public)


def presents(profile: Profile, *, claim: str, trusted_authority_keys: Set[bytes]) -> bool:
    """A CONSUMER's check: does this participant hold a VALID attestation for `claim` from an authority
    whose KEY the consumer trusts? Trust binds to the key set the consumer supplies — Atlas anoints no
    root, so a consumer that doesn't trust an authority rejects it even if the signature is valid."""
    return any(a.subject == profile.handle and a.claim == claim and verify_attestation(a)
               and a.authority.encode() in trusted_authority_keys
               for a in profile.attestations)
