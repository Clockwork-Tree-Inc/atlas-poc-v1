"""Atlas PoLE coin economy — Foundation-run, earned-only, no company allocation.

  * `pole`   — Proof of Living Entropy: participation proofs from devices collecting living/ambient
               entropy, mintable only by a live unique person; aggregated at the server.
  * `policy` — the issuance engine: UBI-first (cost-of-living-indexed, real value preserved), then
               variable rewards, funded by the business tithe first and minting second, with
               supply-growth controls. Governed signals (col_index, value_index) are injected.
  * `coin`   — the transferable, divisible Atlas PoLE coin ledger; no company account, earned-only.

Python reference of record; Swift parity follows.
"""
from .coin import (
    FOUNDATION,
    NAME,
    TICKER,
    BetaReceiptsOnly,
    Coin,
    LedgerError,
    Mode,
    account_for,
)
from .commerce import Booking, BookingBook, Sale, pay_listing_fee, purchase
from .governance import IndexGovernance, IndexVote, QuorumError
from .onramp import FiatReserve, deposit_fiat
from .transparency import (
    Entry,
    IdentityRequiredError,
    TransparencyLedger,
    business_listing_fee,
    business_sale,
)
from .pole import NotLiveError, PoLEPool, PoLEProof, collect_pole
from .redemption import ClosedLoop, ClosedLoopError, FiatRedemption, RedemptionGate
from .policy import (
    EconomyState,
    IssuanceResult,
    PolicyParams,
    apply_issuance,
    distribute_vrp,
    issue,
    simulate,
)

__all__ = [
    "TICKER", "NAME", "FOUNDATION", "Coin", "LedgerError", "account_for", "Mode", "BetaReceiptsOnly",
    "PoLEProof", "PoLEPool", "collect_pole", "NotLiveError",
    "PolicyParams", "EconomyState", "IssuanceResult",
    "issue", "distribute_vrp", "apply_issuance", "simulate",
    "Sale", "Booking", "BookingBook", "purchase", "pay_listing_fee",
    "FiatReserve", "deposit_fiat",
    "RedemptionGate", "ClosedLoop", "FiatRedemption", "ClosedLoopError",
    "TransparencyLedger", "Entry", "IdentityRequiredError", "business_sale", "business_listing_fee",
    "IndexGovernance", "IndexVote", "QuorumError",
]
