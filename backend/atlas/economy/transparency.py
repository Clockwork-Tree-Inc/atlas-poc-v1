"""Organization transparency — privacy for people, accountability for businesses.

Individuals stay private (unlinkable personas, private transfers). BUSINESSES — individual sole
traders or companies — must operate in the open: to trade commercially a business must be
IDENTIFIED (a verified real-world entity, not an anonymous persona), and every commercial action
is written to an append-only, hash-chained, PUBLICLY AUDITABLE ledger. So a business's books can
be audited by anyone and there is no dark money in the shadows — while the CUSTOMER on the other
side of each transaction stays pseudonymous. Privacy, not piracy.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import List, Optional, Set

from .coin import Coin
from .commerce import DEFAULT_FEE_BP, Sale, pay_listing_fee, purchase

_ZERO = b"\x00" * 32


def _h(*parts: bytes) -> bytes:
    m = hashlib.sha3_256()
    for p in parts:
        m.update(len(p).to_bytes(4, "big"))
        m.update(p)
    return m.digest()


class IdentityRequiredError(Exception):
    """A business must be identified to operate commercially."""


@dataclass(frozen=True)
class Entry:
    business: str        # IDENTIFIED business id — never a private persona
    kind: str            # "sale" | "listing_fee" | "booking"
    amount: int
    fee: int             # the tithe portion
    counterparty: str    # MAY be a pseudonym — customer privacy is preserved
    epoch: int
    prev: bytes          # hash-chain link (tamper-evidence)

    def digest(self) -> bytes:
        return _h(b"atlas/txlog", self.business.encode(), self.kind.encode(),
                  self.amount.to_bytes(8, "big"), self.fee.to_bytes(8, "big"),
                  self.counterparty.encode(), self.epoch.to_bytes(8, "big"), self.prev)


@dataclass
class TransparencyLedger:
    """Append-only, hash-chained, publicly auditable record of business commercial activity."""
    _entries: List[Entry] = field(default_factory=list)
    _identified: Set[str] = field(default_factory=set)

    def register_business(self, business: str, *, identified: bool) -> None:
        """Admit a business. It MUST be identified (real-world entity verified) — anonymous
        commercial operation is refused by design."""
        if not identified:
            raise IdentityRequiredError("a business must be IDENTIFIED to operate commercially")
        self._identified.add(business)

    def is_identified(self, business: str) -> bool:
        return business in self._identified

    def _head(self) -> bytes:
        return self._entries[-1].digest() if self._entries else _ZERO

    def head(self) -> bytes:
        """The chain head — the public ROOT to anchor. Publishing this immutably checkpoints the
        books up to now WITHOUT revealing any entry (a hash, not content)."""
        return self._head()

    def record(self, *, business: str, kind: str, amount: int, fee: int,
               counterparty: str, epoch: int) -> Entry:
        if business not in self._identified:
            raise IdentityRequiredError(f"business {business!r} is not identified — cannot operate")
        e = Entry(business, kind, amount, fee, counterparty, epoch, self._head())
        self._entries.append(e)
        return e

    def audit(self, business: Optional[str] = None) -> List[Entry]:
        """Public audit: every entry, or one business's full books. Nothing is hidden."""
        return [e for e in self._entries if business is None or e.business == business]

    def verify_chain(self) -> bool:
        """The books are tamper-evident: any edit/reorder/deletion breaks the chain."""
        prev = _ZERO
        for e in self._entries:
            if e.prev != prev:
                return False
            prev = e.digest()
        return True


def business_sale(coin: Coin, ledger: TransparencyLedger, *, seller: str, buyer: str, item: bytes,
                  amount: int, epoch: int, fee_bp: int = DEFAULT_FEE_BP) -> Sale:
    """A business sells to a (pseudonymous) customer: run the APLC purchase AND record the business
    side transparently. The seller must be an identified business; the buyer stays private."""
    if not ledger.is_identified(seller):
        raise IdentityRequiredError(f"seller {seller!r} is not an identified business")
    sale = purchase(coin, buyer=buyer, seller=seller, item=item, amount=amount,
                    epoch=epoch, fee_bp=fee_bp)
    ledger.record(business=seller, kind="sale", amount=sale.amount, fee=sale.fee,
                  counterparty=buyer, epoch=epoch)
    return sale


def business_listing_fee(coin: Coin, ledger: TransparencyLedger, *, business: str, amount: int,
                         epoch: int) -> int:
    """A business pays its listing/membership fee (→ tithe) and it is recorded transparently."""
    if not ledger.is_identified(business):
        raise IdentityRequiredError(f"business {business!r} is not identified")
    paid = pay_listing_fee(coin, business=business, amount=amount)
    ledger.record(business=business, kind="listing_fee", amount=paid, fee=paid,
                  counterparty="foundation", epoch=epoch)
    return paid
