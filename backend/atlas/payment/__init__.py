"""Air-gapped payment & presence module — arm-per-use flow (Payment spec §4).

⚠️  SECURITY-CRITICAL · PROTOCOL-LOGIC SIMULATION ONLY ⚠️
This package implements the *protocol logic* of the two-factor arm-per-use
payment authorization so it can be tested adversarially and handed to a
reviewer. It does NOT prove the air gap: the air-gap property only exists with
the physical Card 2 over a real NFC/APDU session (Payment spec §1 "Step Zero").
Per the spec, a software card MUST NOT be presented as air-gapped. Nothing here
is for value-bearing use until a cryptographer + the §11 external audit sign off
(Payment spec §8). See PAYMENT_MODULE.md for the assessment package.

The two-factor air gap (§3): a payment needs BOTH the physical card (signer) AND
the phone's arming (verified-human authorization). A stolen card alone cannot
sign (no arming); a compromised phone alone cannot sign (no card key). Neither
element ever holds the other's secret.
"""

from .descriptor import TransactionDescriptor
from .intent import SideButtonIntent, IntentToken
from .enclave_arming import EnclaveArmingAuthority, Arming, ArmingRefused
from .card import PaymentCard, CardRefused
from .nullifier import NullifierRegistry, PaymentVerifier, DoubleSpend

__all__ = [
    "TransactionDescriptor",
    "SideButtonIntent", "IntentToken",
    "EnclaveArmingAuthority", "Arming", "ArmingRefused",
    "PaymentCard", "CardRefused",
    "NullifierRegistry", "PaymentVerifier", "DoubleSpend",
]
