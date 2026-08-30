"""Identity, Real-ID binding & unlinkability module (Real-ID spec).

⚠️  SHOWCASE BUILD · TEST/DUMMY IDENTITY DATA ONLY ⚠️
This extends the existing TSK → System-ID → children tree with: a dedicated
real-ID child, verification-status inheritance (prove "a real human is verified
behind this" without exposing the ID), graduated assurance levels L0/L1/L2,
non-custodial storage, two auth modes, per-epoch unlinkability (closes threat
T-20), and a behavioural duress channel (closes threat T-7).

It demonstrates the MECHANISM with stand-in data. It must NOT ingest any real
person's real government/financial identity — that is a separate, regulated
legal/compliance project (Real-ID spec §0, §8.3). Goes to the §11 audit before
any non-showcase use; see REALID_MODULE.md.

Note on the inheritance crypto: the unlinkable verification proof uses REAL BBS+
selective-disclosure credentials via a vetted library (`ursa-bbs-signatures`,
Hyperledger Ursa) — NOT a hand-rolled scheme. Audit items: Ursa is archived
(track a maintained successor), BBS+ is classical not post-quantum, and
involuntary opening needs a group-signature/verifiable-encryption extension. See
verification.py and REALID_MODULE.md.
"""

from .levels import AssuranceLevel
from .verification import (
    AtlasVerificationAuthority, VerificationRecord, VerificationCredential, InheritedProof,
)
from .realid_child import RealIDVault, ConsentRequired, SurfaceLog
from .storage import OnDeviceStore, SplitStore, NonCustodyError
from .modes import bind_to_external, atlas_as_identity
from .pseudonym import epoch_pseudonym, DPCounter
from .duress import DuressEnrolment, authenticate, AuthOutcome
from .credential_scheme import (
    CredentialScheme, BBSCredentialScheme, MockCredentialScheme,
    ml_dsa_authenticity_sign, ml_dsa_authenticity_verify,
)
from .pqc_tunnel import SealedPresentation, seal_presentation, open_presentation
from .rerooting import (
    reroot_system_id, rotate_tsk, FullRecoveryParams, RerootError, OperatorForbidden,
)

__all__ = [
    "AssuranceLevel",
    "AtlasVerificationAuthority", "VerificationRecord", "VerificationCredential", "InheritedProof",
    "RealIDVault", "ConsentRequired", "SurfaceLog",
    "OnDeviceStore", "SplitStore", "NonCustodyError",
    "bind_to_external", "atlas_as_identity",
    "epoch_pseudonym", "DPCounter",
    "DuressEnrolment", "authenticate", "AuthOutcome",
    "CredentialScheme", "BBSCredentialScheme", "MockCredentialScheme",
    "ml_dsa_authenticity_sign", "ml_dsa_authenticity_verify",
    "SealedPresentation", "seal_presentation", "open_presentation",
    "reroot_system_id", "rotate_tsk", "FullRecoveryParams", "RerootError", "OperatorForbidden",
]
