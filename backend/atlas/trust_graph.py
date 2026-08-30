"""Trust graph — orgs verified by the APPROPRIATE real-world authority, people bound to real-world
identities, and everyone linked in ONE signed, walkable graph.

This is the assembly layer over `participant.Attestation`: it turns isolated "authority X signed a claim
about Y" edges into a graph you can WALK. The two things it answers, symmetric to the person eID:

  * ORGS are verified by an authority of the RIGHT KIND. A university is only "accredited" if the edge
    comes from an accreditor, and that accreditor is itself authorized (an `authorizes:accreditor` edge)
    by a higher authority, chaining up to a root the CONSUMER trusts. Same for a registry registering a
    legal entity. Downstream accreditation flows: a root authorizes a national body, which authorizes a
    regional one, which accredits the school — every hop signed, revocable, walkable.

  * PEOPLE are bound to real-world identities (a `real-id` edge from a trusted verifier — the eID) and
    LINKED to verified orgs (a school certifies its graduate; an org affiliates its officer). An
    accredited doctor and an accredited doctor under a DIFFERENT root recognize each other for free:
    anyone who trusts a given root can walk the path to it.

VERIFICATION, NOT AUTHORITY (same as everywhere): Atlas anoints no root. The verifier supplies the set
of `trusted_roots` (and, for identity, `trusted_verifier_keys`); every check is fail-closed and every
success returns the `Path` it walked, so the trail is auditable. Nodes are identified by their PUBLIC
KEY encoding, so an org that is a subject in one edge can be the issuer in the next — that is what makes
the graph chain.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from .crypto.sign import HybridSigKeypair, HybridSigPublic
from .economy.supply_gate import REAL_ID_CLAIM, REGISTRATION_CLAIM
from .issuers import credential_id
from .participant import Attestation, issue_attestation, verify_attestation

# --- remits: what KIND of authority an edge requires the issuer to be ---
ACCREDITOR = "accreditor"   # entitled to accredit organizations
REGISTRY = "registry"       # entitled to register legal entities
LICENSOR = "licensor"       # entitled to license/certify individuals


def authorizes_claim(remit: str) -> str:
    """A grantor delegates a remit downstream — the edge that makes someone an authority of a kind."""
    return f"authorizes:{remit}"


def accredits_claim(kind: str) -> str:
    """An accreditor attests a subject is a bona-fide org of `kind` (e.g. accredits:university)."""
    return f"accredits:{kind}"


def certifies_claim(qualification: str) -> str:
    """A verified org (or a licensor) attests a person holds a qualification (e.g. certifies:md)."""
    return f"certifies:{qualification}"


def affiliated_claim(role: str) -> str:
    """A verified org attests a person is affiliated in a role (e.g. affiliated:registrar)."""
    return f"affiliated:{role}"


def registered_claim(number: str = "") -> str:
    """A registry's edge, optionally binding the real-world registry NUMBER (company no., EIN, ...) —
    `registered` (bare) or `registered:<number>`. Binding the number is what makes a duplicate
    registration of the SAME org detectable."""
    return REGISTRATION_CLAIM if not number else f"{REGISTRATION_CLAIM}:{number}"


def registration_number(att: Attestation) -> Optional[str]:
    """The real-world number a registration edge binds, or None if it is a bare `registered` edge."""
    if att.claim == REGISTRATION_CLAIM:
        return None
    prefix = REGISTRATION_CLAIM + ":"
    return att.claim[len(prefix):] if att.claim.startswith(prefix) else None


def _is_registration(claim: str) -> bool:
    return claim == REGISTRATION_CLAIM or claim.startswith(REGISTRATION_CLAIM + ":")


def _key(pub: HybridSigPublic) -> bytes:
    return pub.encode()


class TrustGraphError(Exception):
    ...


# --- edge constructors — thin signed wrappers; the SUBJECT is the subject's key encoding so an org
#     that is a subject here can be an issuer in the next hop (this is what lets the graph chain) ---

def authorize(grantor: HybridSigKeypair, *, grantee: HybridSigPublic, remit: str,
              grantor_name: str = "", epoch: int = 0) -> Attestation:
    """Delegate `remit` to `grantee`. Valid only if the grantor itself holds the remit (or is a root)."""
    return issue_attestation(grantor, authority_name=grantor_name, subject=_key(grantee),
                             claim=authorizes_claim(remit), epoch=epoch)


def accredit(authority: HybridSigKeypair, *, org: HybridSigPublic, kind: str,
             authority_name: str = "", epoch: int = 0) -> Attestation:
    return issue_attestation(authority, authority_name=authority_name, subject=_key(org),
                             claim=accredits_claim(kind), epoch=epoch)


def register(registry: HybridSigKeypair, *, org: HybridSigPublic, number: str = "",
             registry_name: str = "", epoch: int = 0) -> Attestation:
    """A registry registers a legal entity, optionally binding its real-world `number` so a second,
    competing registration of the same number is visible (see `TrustGraph.registration_conflict`)."""
    return issue_attestation(registry, authority_name=registry_name, subject=_key(org),
                             claim=registered_claim(number), epoch=epoch)


def certify(issuer: HybridSigKeypair, *, person: HybridSigPublic, qualification: str,
            issuer_name: str = "", epoch: int = 0) -> Attestation:
    return issue_attestation(issuer, authority_name=issuer_name, subject=_key(person),
                             claim=certifies_claim(qualification), epoch=epoch)


def affiliate(org: HybridSigKeypair, *, person: HybridSigPublic, role: str,
              org_name: str = "", epoch: int = 0) -> Attestation:
    return issue_attestation(org, authority_name=org_name, subject=_key(person),
                             claim=affiliated_claim(role), epoch=epoch)


def bind_real_identity(verifier: HybridSigKeypair, *, person: HybridSigPublic, verifier_name: str = "",
                       epoch: int = 0) -> Attestation:
    """The eID edge: a trusted verifier binds a person to a real-world legal identity."""
    return issue_attestation(verifier, authority_name=verifier_name, subject=_key(person),
                             claim=REAL_ID_CLAIM, epoch=epoch)


@dataclass(frozen=True)
class Path:
    """The audit trail a verification walked — root-first. Empty means the node WAS the trusted root."""
    edges: Tuple[Attestation, ...] = ()

    def authorities(self) -> Tuple[str, ...]:
        """Display labels of the authorities along the path (labels, not trust)."""
        return tuple(e.authority_name for e in self.edges)


class TrustGraph:
    """A walkable set of signed edges. The verifier owns the trust: it supplies `trusted_roots`, and
    `now` gates edge validity. Only signature-valid edges are ever admitted; revocation and time are
    applied at walk time so a published revocation can land without rebuilding the graph."""

    def __init__(self, *, trusted_roots: Set[bytes], revoked: Optional[Set[bytes]] = None,
                 now: int = 0) -> None:
        self.trusted_roots: Set[bytes] = set(trusted_roots)
        self.revoked: Set[bytes] = set(revoked or set())
        self.now: int = now
        self._by_subject: Dict[bytes, List[Attestation]] = {}

    def add(self, att: Attestation) -> "TrustGraph":
        """Admit a signature-valid edge (fail-closed on forgery). Trust/time/revocation are walk-time."""
        if not verify_attestation(att):
            raise TrustGraphError("edge signature invalid")
        self._by_subject.setdefault(att.subject, []).append(att)
        return self

    def revoke(self, att: Attestation) -> None:
        """Publish a revocation (a struck-off accreditor, a rescinded license) — forward-effective."""
        self.revoked.add(credential_id(att))

    def _live(self, att: Attestation) -> bool:
        return credential_id(att) not in self.revoked and att.epoch <= self.now

    def _edges_to(self, subject_key: bytes) -> Tuple[Attestation, ...]:
        return tuple(self._by_subject.get(subject_key, ()))

    def _all_edges(self) -> Tuple[Attestation, ...]:
        return tuple(e for edges in self._by_subject.values() for e in edges)

    # --- the walker ---

    def has_remit(self, authority_key: bytes, remit: str,
                  _seen: Optional[Set[bytes]] = None) -> Optional[Path]:
        """Is `authority_key` entitled to act as `remit`? True if it is a trusted root, or holds an
        `authorizes:<remit>` edge from a grantor that ITSELF holds the remit — chaining to a root.
        Cycle-guarded. Returns the delegation Path (root-first), or None."""
        if authority_key in self.trusted_roots:
            return Path(())
        seen = _seen or set()
        if authority_key in seen:
            return None
        seen = seen | {authority_key}
        want = authorizes_claim(remit)
        for e in self._edges_to(authority_key):
            if e.claim == want and self._live(e):
                up = self.has_remit(_key(e.authority), remit, seen)
                if up is not None:
                    return Path(up.edges + (e,))
        return None

    def verify_org(self, org: HybridSigPublic, *, kind: Optional[str] = None) -> Optional[Path]:
        """An org is verified iff an ACCREDITOR accredits it (optionally of a specific `kind`) OR a
        REGISTRY registers it, where that authority chains to a trusted root. Returns the Path walked."""
        for e in self._edges_to(_key(org)):
            if not self._live(e):
                continue
            if e.claim.startswith("accredits:") and (kind is None or e.claim == accredits_claim(kind)):
                up = self.has_remit(_key(e.authority), ACCREDITOR)
                if up is not None:
                    return Path(up.edges + (e,))
            elif _is_registration(e.claim):
                up = self.has_remit(_key(e.authority), REGISTRY)
                if up is not None:
                    return Path(up.edges + (e,))
        return None

    def registrations_of(self, number: str, *,
                         registry_key: Optional[bytes] = None) -> Tuple[Attestation, ...]:
        """Every LIVE registration edge that binds real-world `number` (optionally from one registry).
        The registry is meant to keep a number unique; this lets ANYONE audit that it did."""
        want = registered_claim(number)
        return tuple(e for e in self._all_edges()
                     if e.claim == want and self._live(e)
                     and (registry_key is None or _key(e.authority) == registry_key))

    def registration_conflict(self, number: str, *, registry_key: Optional[bytes] = None) -> bool:
        """True if `number` is registered to MORE THAN ONE distinct org key — i.e. someone tried to
        register your org. Surface this to the rightful holder; the registry revokes the impostor."""
        return len({e.subject for e in self.registrations_of(number, registry_key=registry_key)}) > 1

    def sole_registrant(self, org: HybridSigPublic, number: str, *,
                        registry_key: Optional[bytes] = None) -> bool:
        """True iff `org` is the ONE key holding a live registration for `number`. False both when it
        does not hold it and when the number is contested — a clean 'is this uniquely mine' check."""
        subs = {e.subject for e in self.registrations_of(number, registry_key=registry_key)}
        return subs == {_key(org)}

    def verify_qualification(self, person: HybridSigPublic, qualification: str) -> Optional[Path]:
        """A person holds `qualification` iff a certifier attests it AND that certifier is either a
        verified org (a school certifying its graduate) or a licensor chaining to a root."""
        want = certifies_claim(qualification)
        for e in self._edges_to(_key(person)):
            if e.claim == want and self._live(e):
                via_org = self.verify_org(e.authority)
                if via_org is not None:
                    return Path(via_org.edges + (e,))
                via_lic = self.has_remit(_key(e.authority), LICENSOR)
                if via_lic is not None:
                    return Path(via_lic.edges + (e,))
        return None

    def verify_affiliation(self, person: HybridSigPublic, org: HybridSigPublic, role: str) -> Optional[Path]:
        """A person is affiliated to a VERIFIED org in `role` — the org vouches for its own people, and
        the org itself must verify. Returns the Path (the org's verification plus the affiliation edge)."""
        want = affiliated_claim(role)
        org_key = _key(org)
        for e in self._edges_to(_key(person)):
            if e.claim == want and self._live(e) and _key(e.authority) == org_key:
                up = self.verify_org(org)
                if up is not None:
                    return Path(up.edges + (e,))
        return None

    def has_real_identity(self, person: HybridSigPublic, *, trusted_verifier_keys: Set[bytes]) -> bool:
        """A person is bound to a real-world identity iff a verifier the consumer trusts issued the
        eID (`real-id`) edge and it is live. This is the person-side symmetric of org accreditation."""
        for e in self._edges_to(_key(person)):
            if e.claim == REAL_ID_CLAIM and self._live(e) and _key(e.authority) in trusted_verifier_keys:
                return True
        return False
