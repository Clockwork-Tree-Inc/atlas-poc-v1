"""Transaction descriptor (Payment spec §4).

transaction_descriptor = { amount, recipient_id, nonce, timestamp, epoch }

Canonical bytes are what BOTH the Enclave arming and the card signature commit
to, so amount/recipient/nonce are bound into every signature (single-use,
non-replayable).
"""

from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass(frozen=True)
class TransactionDescriptor:
    amount: int            # smallest unit (e.g. cents); integer to avoid float drift
    recipient_id: str
    nonce: str             # fresh per payment (hex); the nullifier key
    timestamp: int         # unix seconds
    epoch: int             # beacon epoch this payment is bound to

    def canonical(self) -> bytes:
        return json.dumps(
            {"amount": self.amount, "recipient_id": self.recipient_id, "nonce": self.nonce,
             "timestamp": self.timestamp, "epoch": self.epoch},
            sort_keys=True, separators=(",", ":"),
        ).encode()

    def well_formed(self) -> bool:
        return (isinstance(self.amount, int) and self.amount > 0
                and bool(self.recipient_id) and bool(self.nonce)
                and self.timestamp > 0 and self.epoch >= 0)
