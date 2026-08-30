"""Atlas PoLE coin (APLC) — the transferable, divisible value token.

Run ENTIRELY by the FOUNDATION so the value reaches people, not the company:
  * there is NO company/founder account and NO premine — structurally no path to one exists;
  * coin is EARNED-ONLY — it enters circulation solely via `economy.policy` issuance
    (UBI first, then variable rewards, then the Foundation running/charity pool);
  * the protocol sets NO price — value is decided by the market.
There is no public mint; only `economy.policy.apply_issuance` (the issuance path) calls `_mint`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict

TICKER = "APLC"
NAME = "Atlas PoLE coin"
FOUNDATION = "foundation"  # running-costs + charitable-spillover pool; NOT company profit


class LedgerError(Exception):
    ...


class Mode(Enum):
    """BETA ships with RECEIPTS ONLY — no live monetary token, so there is no securities exposure
    during testing. Activity in beta is tracked by NON-MONETARY receipts (soul-bound participation
    + the provenance/transparency records). The transferable Atlas PoLE coin becomes live money only
    at FULL release."""
    BETA = "beta"
    FULL = "full"


class BetaReceiptsOnly(LedgerError):
    """Raised when a monetary coin operation is attempted in BETA — receipts only until FULL."""


def account_for(person_tag: bytes) -> str:
    """A holder account derived from a person's unlinkable tag. There is deliberately no
    'company' account constructor anywhere."""
    return "p:" + person_tag.hex()


@dataclass
class Coin:
    """The APLC ledger — integer base units (no floats), transferable + divisible.

    In `Mode.BETA` the monetary operations (transfer/mint) are DISABLED — the system runs on
    non-monetary receipts; the coin becomes live money only in `Mode.FULL` (full release)."""
    _bal: Dict[str, int] = field(default_factory=dict)
    supply: int = 0
    mode: Mode = Mode.FULL

    def balance(self, account: str) -> int:
        return self._bal.get(account, 0)

    def accounts(self) -> Dict[str, int]:
        return {a: b for a, b in self._bal.items() if b}

    def transfer(self, frm: str, to: str, amount: int) -> None:
        if self.mode is Mode.BETA:
            raise BetaReceiptsOnly("no monetary transfers in beta — receipts only until full release")
        if amount <= 0:
            raise LedgerError("amount must be positive")
        if self.balance(frm) < amount:
            raise LedgerError("insufficient balance")
        if frm == to:
            return
        self._bal[frm] = self.balance(frm) - amount
        self._bal[to] = self.balance(to) + amount

    def _mint(self, to: str, amount: int) -> None:
        """INTERNAL earned-only mint — reached only through the issuance path. No company
        account is ever a target; the only non-person target is the Foundation pool."""
        if self.mode is Mode.BETA:
            raise BetaReceiptsOnly("no monetary minting in beta — receipts only until full release")
        if amount < 0:
            raise LedgerError("cannot mint a negative amount")
        if amount == 0:
            return
        self._bal[to] = self.balance(to) + amount
        self.supply += amount
