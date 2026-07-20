"""The two authentication modes (Real-ID spec §5).

Mode 1 — bind to an external identity: Atlas supplies the verified-live-human
proof (L0/L1); an external service owns the identity. Atlas stores none of it.

Mode 2 — Atlas as the identity: Atlas holds the (test) real-world ID via the
real-ID child (non-custodial), and performs full auth itself (L2 surface).

Same proof underneath: the verified-live-human proof is the constant; only the
identity-of-record holder differs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .levels import AssuranceLevel
from .realid_child import RealIDVault
from .verification import AtlasVerificationAuthority, InheritedProof


@dataclass
class ExternalBinding:
    """A mock external service's record. Atlas does NOT store the external
    identity — the service does. Atlas only handed over a live-human proof."""

    mock_service: str
    bound_proof_level: AssuranceLevel
    atlas_stored_external_identity: bool = False  # always False — Atlas stores none


def bind_to_external(*, bbs_key, proof: InheritedProof,
                     required: AssuranceLevel, mock_service: str) -> ExternalBinding:
    """Mode 1: present a verified-live-human / inherited BBS+ proof to a mock
    service, which binds it to its own account. Atlas stores nothing of the
    external id."""
    if not AtlasVerificationAuthority.verify_proof(bbs_key, proof, required=required):
        raise ValueError("external service rejected the Atlas proof")
    return ExternalBinding(mock_service=mock_service, bound_proof_level=proof.level)


@dataclass
class AtlasIdentityResult:
    surfaced_test_id: bytes
    level: AssuranceLevel


def atlas_as_identity(*, vault: RealIDVault, consent: bool, context: str) -> AtlasIdentityResult:
    """Mode 2: a context requests L2; the user consents; the real-ID child
    surfaces the (test) ID on-device; Atlas authenticates directly; logged."""
    material = vault.surface_legal_identity(consent=consent, context=context)
    return AtlasIdentityResult(surfaced_test_id=material, level=AssuranceLevel.L2)
