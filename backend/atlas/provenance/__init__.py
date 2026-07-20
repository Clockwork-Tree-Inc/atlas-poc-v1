"""Content provenance and capture (§8, §10.2 capstone).

Sign content with a liveness-gated authorship pseudonym (a System-ID child),
bind the epoch-key timestamp, run presentation-attack detection at capture, and
anchor the content hash to a simple ledger stand-in (content off-chain).

Honest boundary (§8.2): software capture-provenance proves the content was
captured through an attested flow, by a verified live human, at a verifiable
time, PAD-checked, and unmodified since. It does NOT prove the camera saw a real
scene — the analog hole and sub-OS sensor injection remain. Below-the-OS sensor
attestation (C2PA direction) is the production path.
"""

from .ledger import LedgerStub, AnchorReceipt
from .pad import pad_check, PADResult, PADRejected
from .live_binding import (
    PublicWitnessRegistry, LiveProvenanceBinding, bind_live_provenance, verify_live_provenance,
)
from .capture import (
    ProvenanceBundle,
    ProvenanceVerdict,
    CaptureMetadata,
    sign_capture,
    verify_provenance,
    resolve_author_under_cause,
    NotLiveError,
)

__all__ = [
    "LedgerStub", "AnchorReceipt",
    "pad_check", "PADResult", "PADRejected",
    "PublicWitnessRegistry", "LiveProvenanceBinding",
    "bind_live_provenance", "verify_live_provenance",
    "ProvenanceBundle", "ProvenanceVerdict", "CaptureMetadata",
    "sign_capture", "verify_provenance", "resolve_author_under_cause", "NotLiveError",
]
