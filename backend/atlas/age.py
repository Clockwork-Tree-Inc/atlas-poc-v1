"""Age assurance — an eID-rooted, consumable, unlinkable, bidirectional age gate.

Separate children from adults WITHOUT surveilling either. The chain:

  eID (private)  ->  age-verifier AUTHORITY  ->  consumable age TOKENS  ->  a space's GATE

  * eID SOURCE (#22 slice). An eID reader extracts the issuer-signed birth year (ICAO passive
    authentication in production; modelled here as an eID-authority signature). The raw eID is never
    stored; only the birth year is read, and only to derive a band.
  * AGE-VERIFIER AUTHORITY. A credential authority (a gov office / certified age-verifier — just a
    participant, see participant.py) verifies the eID and issues a SUPPLY of single-use age tokens
    for the satisfied band ("18+" / "21+" / "under-18"). It attests the BAND only — never the birth
    date, never identity.
  * CONSUMABLE TOKENS. Each token is single-use (a fresh serial); a presentation spends one; different
    tokens don't correlate (e-cash style), so a game maker/server can GATE but cannot track a user or
    link them across services. Band-only, no identity — child-safety without child-surveillance.
  * BIDIRECTIONAL GATE + GUARDIAN EXCEPTION. Adult-only spaces require an 18+/21+ token; child-only
    spaces require an under-18 token — EXCEPT an eID-verified adult holding a GUARDIAN attestation for
    that space (participant.Attestation) may enter to supervise.

HONEST BOUNDARY: tokens are near-bearer — issuance is gated (eID + a live human) and presentation
should carry a fresh liveness proof, so a bot can't spend a stolen token; but an adult physically
handing a child a token is a residual (as with any ID check). Full holder-binding WITH cross-verifier
unlinkability is the ZK/BBS anonymous-credential upgrade (realid BBS + the DLEQ-VRF nullifier).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Set

from .crypto.primitives import H
from .crypto.sign import HybridSigKeypair, HybridSigPublic, sign, verify
from .participant import Attestation, verify_attestation

# A band implies the weaker adult band: a 21+ token also satisfies an 18+ gate.
_IMPLIES = {"21+": {"21+", "18+"}, "18+": {"18+"}, "under-18": {"under-18"}}


class AgeError(Exception):
    ...


def bands_for(birth_year: int, ref_year: int) -> Set[str]:
    """The bands a birth year satisfies as of `ref_year`. Exactly one of 18+/under-18, plus 21+."""
    age = ref_year - birth_year
    bands = {"18+"} if age >= 18 else {"under-18"}
    if age >= 21:
        bands.add("21+")
    return bands


def satisfies(token_band: str, required: str) -> bool:
    return required in _IMPLIES.get(token_band, {token_band})


# --------------------------------------------------------------------------- #
# eID source (#22 slice)
# --------------------------------------------------------------------------- #
@dataclass
class EIDAssertion:
    """An eID reader's extract + the issuer's signature over it (models ICAO passive auth). Bound to
    the persona handle at read time; only `birth_year` is used, and the raw eID is never stored."""
    issuer_name: str
    issuer: HybridSigPublic
    subject: bytes
    birth_year: int
    sig: bytes = b""

    def body(self) -> bytes:
        return H(b"atlas/eid/v1", self.issuer_name.encode(), self.subject, str(self.birth_year).encode())


def issue_eid_assertion(issuer_kp: HybridSigKeypair, *, issuer_name: str, subject: bytes,
                        birth_year: int) -> EIDAssertion:
    a = EIDAssertion(issuer_name=issuer_name, issuer=issuer_kp.public, subject=subject,
                     birth_year=birth_year)
    a.sig = sign(issuer_kp, a.body())
    return a


def verify_eid_assertion(a: EIDAssertion) -> bool:
    return verify(a.issuer, a.body(), a.sig)


# --------------------------------------------------------------------------- #
# Consumable age tokens
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class AgeToken:
    """A single-use, band-only, identity-free age token. `serial` makes it one-time; tokens don't
    correlate to each other or to the holder."""
    authority_name: str
    authority: HybridSigPublic
    band: str
    serial: bytes
    sig: bytes

    def body(self) -> bytes:
        return H(b"atlas/age-token/v1", self.authority_name.encode(), self.band.encode(), self.serial)


def issue_age_tokens(authority_kp: HybridSigKeypair, *, authority_name: str,
                     eid: EIDAssertion, ref_year: int, band: str, count: int,
                     serials: List[bytes]) -> List[AgeToken]:
    """The age-verifier verifies the eID, checks it satisfies `band`, and mints `count` single-use
    tokens for that band. `serials` are caller-supplied fresh randoms (Math.random is unavailable in
    this reference; the device/authority supplies entropy)."""
    if not verify_eid_assertion(eid):
        raise AgeError("eID assertion does not verify")
    if band not in bands_for(eid.birth_year, ref_year):
        raise AgeError(f"eID does not satisfy band {band!r}")
    if len(serials) < count:
        raise AgeError("not enough serials supplied")
    out: List[AgeToken] = []
    for i in range(count):
        t = AgeToken(authority_name=authority_name, authority=authority_kp.public, band=band,
                     serial=serials[i], sig=b"")
        out.append(AgeToken(authority_name=t.authority_name, authority=t.authority, band=t.band,
                            serial=t.serial, sig=sign(authority_kp, t.body())))
    return out


def verify_token(t: AgeToken) -> bool:
    return verify(t.authority, t.body(), t.sig)


# --------------------------------------------------------------------------- #
# The gate — bidirectional, consumable, with the guardian exception
# --------------------------------------------------------------------------- #
def _spend(t: AgeToken, *, required: str, trusted_authority_keys: Set[bytes],
           seen_serials: Set[bytes]) -> bool:
    """Verify + consume a token for `required`. Fails if invalid, from an untrusted authority, wrong
    band, or already spent (single-use). On success the serial is burned."""
    if not verify_token(t):
        return False
    if t.authority.encode() not in trusted_authority_keys:
        return False
    if not satisfies(t.band, required):
        return False
    if t.serial in seen_serials:
        return False                       # already consumed — no replay, no tracking handle
    seen_serials.add(t.serial)
    return True


def admit_adult_space(t: AgeToken, *, trusted_authority_keys: Set[bytes], seen_serials: Set[bytes],
                      required: str = "18+") -> bool:
    """Adult-only space: spend an 18+ (or 21+) token. Minors are excluded (no satisfying token)."""
    return _spend(t, required=required, trusted_authority_keys=trusted_authority_keys,
                  seen_serials=seen_serials)


def _valid_guardian(att: Attestation, *, child_space_id: str,
                    trusted_authority_keys: Set[bytes]) -> bool:
    return (verify_attestation(att)
            and att.claim == f"guardian-in:{child_space_id}"
            and att.authority.encode() in trusted_authority_keys)


def admit_child_space(*, child_space_id: str, trusted_authority_keys: Set[bytes],
                      seen_serials: Set[bytes], token: Optional[AgeToken] = None,
                      guardian_token: Optional[AgeToken] = None,
                      guardian_attestation: Optional[Attestation] = None) -> Optional[str]:
    """Child-only space: a minor's under-18 token admits as 'minor'. An adult is admitted ONLY as
    'guardian' — an 18+ token AND a valid guardian attestation for THIS space. Returns the role
    admitted, or None. Adults without a guardian attestation are excluded."""
    if token is not None and _spend(token, required="under-18",
                                    trusted_authority_keys=trusted_authority_keys,
                                    seen_serials=seen_serials):
        return "minor"
    if (guardian_token is not None and guardian_attestation is not None
            and _valid_guardian(guardian_attestation, child_space_id=child_space_id,
                                trusted_authority_keys=trusted_authority_keys)
            and _spend(guardian_token, required="18+",
                       trusted_authority_keys=trusted_authority_keys, seen_serials=seen_serials)):
        return "guardian"
    return None
