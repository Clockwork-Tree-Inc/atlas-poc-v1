"""Device-attestation contract (TRUST_LAYER.md #11).

The platform-neutral contract for "any device that proves itself worthy": capabilities are
DERIVED from what a device proves live (never asserted), and an assurance tier composes from
them fail-closed. This lives in the Python reference-of-record with parity vectors, so every
platform — iOS, Android, browser, custom hardware — mirrors identical semantics. See `device.py`.
"""
