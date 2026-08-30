"""Credential issuers — the accountable real-world authorities that MINT and REVOKE the attestations
the gates consume. The gates (`economy.supply_gate`, records, polls) check "holds a valid `real-id` /
`registered` / `category:*` attestation from a KEY I trust". This module is the other side: a Real-ID
verifier, a company registry, a sector body — each just a keypair that signs those claims and can
revoke them (a struck-off org, a rescinded credential).

Verification-not-authority: an issuer's power is only that some CONSUMER trusts its KEY. Atlas anoints
no root — a real registry, a notary, a medical college each plug in as an independent issuer key.

Revocation is a PUBLISHED set of revoked credential ids (forward-effective, like all revocation).
A fully unlinkable / no-phone-home revocation is the harder problem (accumulator + periodic anchor);
this published-set form is the honest PoC floor and composes the same attestations.
"""
from __future__ import annotations

from typing import Set

from .crypto.primitives import H
from .crypto.sign import HybridSigKeypair, HybridSigPublic
from .economy.supply_gate import REAL_ID_CLAIM, REGISTRATION_CLAIM
from .participant import Attestation, issue_attestation, verify_attestation


def category_claim(sector: str) -> str:
    """The claim string for a sector credential, e.g. category('healthcare') -> 'category:healthcare'."""
    return f"category:{sector}"


def credential_id(att: Attestation) -> bytes:
    """A stable id for revocation — the hash of the attestation body (issuer+subject+claim+epoch)."""
    return H(b"atlas/credential-id", att.body())


class Issuer:
    """An accountable authority that issues + revokes attestations. Its trust is its KEY, nothing more."""

    def __init__(self, kp: HybridSigKeypair, name: str) -> None:
        self._kp = kp
        self.name = name
        self._revoked: Set[bytes] = set()

    @property
    def public(self) -> HybridSigPublic:
        return self._kp.public

    def issue(self, *, subject: bytes, claim: str, epoch: int = 0) -> Attestation:
        return issue_attestation(self._kp, authority_name=self.name, subject=subject,
                                 claim=claim, epoch=epoch)

    # semantic helpers for the three gate credentials
    def issue_real_id(self, *, subject: bytes, epoch: int = 0) -> Attestation:
        return self.issue(subject=subject, claim=REAL_ID_CLAIM, epoch=epoch)

    def issue_registration(self, *, subject: bytes, epoch: int = 0) -> Attestation:
        return self.issue(subject=subject, claim=REGISTRATION_CLAIM, epoch=epoch)

    def issue_category(self, *, subject: bytes, sector: str, epoch: int = 0) -> Attestation:
        return self.issue(subject=subject, claim=category_claim(sector), epoch=epoch)

    # revocation — a struck-off org / rescinded credential
    def revoke(self, att: Attestation) -> None:
        self._revoked.add(credential_id(att))

    def is_revoked(self, att: Attestation) -> bool:
        return credential_id(att) in self._revoked

    @property
    def revocation_set(self) -> Set[bytes]:
        """The published set of revoked credential ids (what a verifier checks against)."""
        return set(self._revoked)


def valid_credential(att: Attestation, *, trusted_issuer_keys: Set[bytes],
                     revoked: Set[bytes] = frozenset()) -> bool:
    """A credential counts iff: its signature verifies, its issuer key is trusted by the checker, and
    it is not in the published revocation set. (Subject-binding is the consumer's separate check.)"""
    return (verify_attestation(att)
            and att.authority.encode() in trusted_issuer_keys
            and credential_id(att) not in revoked)
