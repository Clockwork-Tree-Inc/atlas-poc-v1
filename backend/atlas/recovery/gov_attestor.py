"""Government-office recovery attestor — a real-world body as a WITTING, INSTITUTIONAL guardian.

A user MAY add a government office (or any accountable institution) to their guardianship as one
custodian. Unlike a silent device-node guardian, the office releases its recovery approval ONLY after
an IN-PERSON re-verification: you show up, it reads your eID (issuer-signed) and confirms a live human
is present, and only then does it sign an approval. It is marked INSTITUTIONAL, so guardianship's
standing invariant — "no all-institutional subset reaches threshold" — guarantees the office (even
colluding with other institutions) can NEVER recover you without a non-institutional, witting guardian
(a live recovery person). The office ATTESTS; it never holds the master key.

This composes the existing pieces: the eID source (age.EIDAssertion), the participant/authority idea
(the office is an authority keyed by its signing key), and the m-of-n guardianship recovery. It adds
only the in-person GATE on the office's approval + the mapping from a signed attestation to a witting
approval label.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Sequence

from ..age import EIDAssertion, verify_eid_assertion
from ..crypto.primitives import H
from ..crypto.sign import HybridSigKeypair, HybridSigPublic, sign, verify
from .guardianship import Guardian, GuardianKind
from .threshold_seal import Custodian


class GovAttestorError(Exception):
    ...


class NotInPerson(GovAttestorError):
    """The office refused to attest — the in-person eID + liveness re-verification did not pass."""


@dataclass
class GovOfficeAttestor:
    """A government office that can serve as one guardian in a user's recovery quorum."""
    name: str
    keypair: HybridSigKeypair

    def custodian_label(self) -> str:
        return f"gov:{self.name}"

    def guardian(self) -> Guardian:
        """The office as a WITTING, INSTITUTIONAL guardian — witting so it must approve (and could
        veto); institutional so the anti-all-institutional invariant keeps it from recovering alone."""
        return Guardian(custodian=Custodian(label=self.custodian_label(), institutional=True),
                        kind=GuardianKind.WITTING)


@dataclass(frozen=True)
class RecoveryAttestation:
    """The office's signed 'I re-verified this human in person for this recovery request.'"""
    office_name: str
    office: HybridSigPublic
    subject: bytes
    request_id: bytes
    sig: bytes

    def body(self) -> bytes:
        return H(b"atlas/gov-recovery/v1", self.office_name.encode(), self.subject, self.request_id)


def attest_recovery(office: GovOfficeAttestor, *, subject_handle: bytes, request_id: bytes,
                    eid: EIDAssertion, live: bool) -> RecoveryAttestation:
    """The in-person GATE: the office signs an approval ONLY IF a valid eID for THIS subject is
    presented AND a live human is present. Otherwise it refuses (NotInPerson) — no remote approval."""
    if not verify_eid_assertion(eid):
        raise NotInPerson("eID assertion did not verify")
    if eid.subject != subject_handle:
        raise NotInPerson("eID does not belong to the recovering persona")
    if not live:
        raise NotInPerson("no live human present at the office")
    body = H(b"atlas/gov-recovery/v1", office.name.encode(), subject_handle, request_id)
    return RecoveryAttestation(office_name=office.name, office=office.keypair.public,
                               subject=subject_handle, request_id=request_id,
                               sig=sign(office.keypair, body))


def verify_recovery_attestation(att: RecoveryAttestation) -> bool:
    return verify(att.office, att.body(), att.sig)


def approvals_from_attestations(offices: Sequence[GovOfficeAttestor],
                                attestations: Iterable[RecoveryAttestation]) -> List[str]:
    """Map VALID office attestations to their guardian approval labels, for feeding into
    reconstruct_under_guardianship's `witting_approvals`. An office with no valid attestation
    contributes no approval — so its in-person re-verification is a hard precondition of its say."""
    by_key = {o.keypair.public.encode(): o for o in offices}
    labels: List[str] = []
    for att in attestations:
        o = by_key.get(att.office.encode())
        if o is not None and verify_recovery_attestation(att):
            labels.append(o.custodian_label())
    return labels
