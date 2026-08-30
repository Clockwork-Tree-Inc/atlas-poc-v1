"""Zero-knowledge proofs (TRUST_LAYER.md #14).

A real, sound, non-interactive ZK proof of liveness: prove a committed liveness score passes the
safety threshold WITHOUT revealing the score (the provisional's `zk_prove(safe, thresholds,
liveness, commit)`). See `liveness_proof.py`.
"""
