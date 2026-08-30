"""AI integration — model-agnostic seam + the cryptographic provenance trail + author-citation economy.

  * `seam`  — a `Model` protocol (open weights wire in — no permission needed), `StubModel` reference,
              a human-rooted `Agent` with scoped/revocable capabilities, and grounded `run_inference`.
  * `trail` — a hash-chained, anchorable `ProvenanceTrail` over the AI+content+rights lifecycle, plus
              `cite_and_reward`: every source attributed, consenting authors paid per use.
"""
from .seam import (
    AccessGrant,
    Agent,
    InferenceResult,
    Model,
    ModelNotEligible,
    Source,
    StubModel,
    admit,
    run_inference,
    web_search,
)
from .trail import (
    Citation,
    ProvenanceTrail,
    TrailEvent,
    cite_and_reward,
    record_grant,
    record_inference,
    record_output,
    record_purchase,
    record_revoke,
)

__all__ = [
    "Source", "InferenceResult", "Model", "StubModel", "Agent", "AccessGrant", "run_inference",
    "ModelNotEligible", "admit", "web_search",
    "ProvenanceTrail", "TrailEvent", "Citation", "cite_and_reward",
    "record_grant", "record_revoke", "record_purchase", "record_inference", "record_output",
]
