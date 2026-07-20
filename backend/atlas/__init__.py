"""Atlas PoC — backend / protocol core.

This package is the Mac-side server/verifier node and the kit-independent
protocol core described in the Atlas PoC Build Spec (FINAL). It is the
substance of Milestone 1 (security + cryptographic identity, no liveness)
plus the simulation-tier liveness math (§11 "Partial (sim)").

Everything here runs and is tested off-device. The iOS/Secure-Enclave/BLE/
camera/JavaCard surfaces are written as Swift source separately and verified
on the Mac + physical kit.
"""

__version__ = "0.1.0"
