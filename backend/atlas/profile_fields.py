"""Custom profile fields — LinkedIn-style claims + endorsements.

Any category you want ("favourite colour", "work", "works at"). Each value is a CLAIM you make and sign.
Then ANYONE — a person or an organization — can ENDORSE that claim by signing it. A value is therefore
either an unendorsed claim or a CONFIRMED claim, and "confirmed" just means one-or-more real signed
endorsements back it. Many endorsers per value: 10 people and 3 organizations can all confirm your
BSc; 2 can confirm your MSc.

Atlas does NOT decide whether an endorser is worth believing — there is no "trusted" label and no trust
judgement in here. The viewer simply sees WHO endorsed each value (every endorsement openable to its
signed proof) and decides for themselves. If they don't rate an endorser, that's their call, not ours.
Swift parity in ProfileFields.swift.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from .crypto.primitives import H
from .crypto.sign import HybridSigKeypair, HybridSigPublic, sign, verify
from .participant import Attestation, issue_attestation, verify_attestation


def field_claim(label: str, value: str) -> str:
    """What an endorser signs to confirm a (label, value), e.g. 'work:BSc'."""
    return f"{label}:{value}"


@dataclass
class ProfileField:
    """One user-defined field: your self-asserted value(s), signed by you, plus any endorsements others
    have added. Endorsements are NOT part of your signature — they accrue over time from other keys."""
    owner: HybridSigPublic
    label: str
    values: Tuple[str, ...]
    endorsements: Tuple[Attestation, ...] = ()
    self_sig: bytes = b""

    def body(self) -> bytes:
        return H(b"atlas/profile-field/v1", self.owner.encode(), self.label.encode(),
                 b"\x00".join(v.encode() for v in self.values))


@dataclass
class Endorser:
    """Who confirmed a value, with the signed proof so a UI can open it and re-verify it."""
    name: str
    key: HybridSigPublic
    proof: Attestation


@dataclass
class ValueEntry:
    """One value of a field and everyone who has endorsed it. `confirmed` is just 'has ≥1 endorser'."""
    value: str
    endorsers: Tuple[Endorser, ...] = ()

    @property
    def confirmed(self) -> bool:
        return len(self.endorsers) > 0


@dataclass
class FieldView:
    """How a field renders: the label, each value with its endorsers, and whether the owner's own
    signature over the claim checks out (a tampered claim is flagged, not shown as genuine)."""
    label: str
    owner_signed: bool
    entries: Tuple[ValueEntry, ...]


def make_field(owner: HybridSigKeypair, label: str, values, *, endorsements=()) -> ProfileField:
    """Create + self-sign a field. `values` is a str or an iterable of str (your claim)."""
    vals = (values,) if isinstance(values, str) else tuple(values)
    f = ProfileField(owner=owner.public, label=label, values=vals, endorsements=tuple(endorsements))
    f.self_sig = sign(owner, f.body())
    return f


def endorse(endorser: HybridSigKeypair, *, subject: HybridSigPublic, label: str, value: str,
            endorser_name: str = "") -> Attestation:
    """Anyone (a person or an org) signs an endorsement of `subject`'s (label, value). Bound to the
    subject and the exact claim, so it can't be reused for a different person or a different value."""
    return issue_attestation(endorser, authority_name=endorser_name, subject=subject.encode(),
                             claim=field_claim(label, value))


def add_endorsements(f: ProfileField, endorsements) -> ProfileField:
    """Attach endorsements gathered from others (does not touch the owner's self-signature)."""
    return ProfileField(owner=f.owner, label=f.label, values=f.values,
                        endorsements=f.endorsements + tuple(endorsements), self_sig=f.self_sig)


def verify_self(f: ProfileField) -> bool:
    """The claim is genuinely the owner's (self-signature over label + values)."""
    return verify(f.owner, f.body(), f.self_sig)


def view(f: ProfileField) -> FieldView:
    """Render the field: each value with the list of everyone who validly endorsed THAT value. No trust
    judgement — just who signed. A UI shows the claim and, next to it, the endorsers (each openable)."""
    owner_key = f.owner.encode()
    entries = []
    for value in f.values:
        want = field_claim(f.label, value)
        endorsers = tuple(Endorser(name=e.authority_name, key=e.authority, proof=e)
                          for e in f.endorsements
                          if verify_attestation(e) and e.subject == owner_key and e.claim == want)
        entries.append(ValueEntry(value=value, endorsers=endorsers))
    return FieldView(label=f.label, owner_signed=verify_self(f), entries=tuple(entries))


@dataclass
class CustomProfile:
    """A fully self-defined profile: an ordered set of custom fields owned by one persona key."""
    owner: HybridSigPublic
    fields: Tuple[ProfileField, ...] = ()

    def with_field(self, f: ProfileField) -> "CustomProfile":
        if f.owner.encode() != self.owner.encode():
            raise ValueError("field owner does not match profile owner")
        return CustomProfile(owner=self.owner, fields=self.fields + (f,))
