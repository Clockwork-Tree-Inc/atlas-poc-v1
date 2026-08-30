"""Liveness layer (PoLE) — Tier 3 simulation (§5, §11 'Partial (sim)').

On real hardware the raw PPG/accelerometer stream arrives from the R10 over BLE
and is gated inside the Secure Enclave. Here we model the Bayesian gate (§5.2),
synthetic presence streams (§11), and the ratchet-paced attestation + removal
states (§5.3, §5.4) so the algorithm — not the biology — is tested.
"""

from .bayes import LivenessGate, PoLEState
from .synthetic import live_stream, spoof_stream, SensorSample
from .attestation import (
    AttestationSubsystem,
    LivenessAttestation,
    RemovalState,
)

__all__ = [
    "LivenessGate",
    "PoLEState",
    "live_stream",
    "spoof_stream",
    "SensorSample",
    "AttestationSubsystem",
    "LivenessAttestation",
    "RemovalState",
]
