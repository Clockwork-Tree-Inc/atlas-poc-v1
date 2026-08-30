"""Atlas authority — cross-boundary permissioned grants (capability delegation).

Rooted, monotonically-attenuating, signature-chained, revocable, personhood-gated capabilities.
One mechanism for Space invitation, org->person credentialing, and org->org accreditation.
See `AUTHORITY_MODEL.md` and `grants.py`."""

from .grants import (
    ACCOUNTABLE,
    ROOT,
    AuthorityError,
    Caveat,
    Grant,
    RightSet,
    Revocation,
    RotationCert,
    delegate,
    grant_id_from_parts,
    issue,
    issue_fs,
    revoke,
    verify_access,
    verify_chain,
)
from .fs_sign import (
    FSError,
    FSPublicKey,
    FSSignature,
    FSSigner,
    fs_keygen,
    fs_verify,
)
from .reroot import (
    ReRoot,
    current_root,
    make_reroot,
)

__all__ = [
    "ACCOUNTABLE",
    "ROOT",
    "AuthorityError",
    "Caveat",
    "Grant",
    "RightSet",
    "Revocation",
    "RotationCert",
    "delegate",
    "grant_id_from_parts",
    "issue",
    "issue_fs",
    "revoke",
    "verify_access",
    "verify_chain",
    "FSError",
    "FSPublicKey",
    "FSSignature",
    "FSSigner",
    "fs_keygen",
    "fs_verify",
    "ReRoot",
    "current_root",
    "make_reroot",
]
