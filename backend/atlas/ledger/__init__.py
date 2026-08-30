"""Individual ledgers + global anchoring (TRUST_LAYER.md #8/#9).

Per-user / per-space append-only ledgers (Merkle accumulators) whose COMMITMENTS — never
content — anchor to a decentralized global ledger, bound to a drand round (the decentralized
timekeeper). A per-conversation policy chooses accountable-anchored vs deniable. See
`TRUST_LAYER.md` for the design of record.
"""
