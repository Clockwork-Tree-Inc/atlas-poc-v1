"""PoLE receipts wallet — portable, identity-free proofs that genuine LIVE ENTROPY was sampled during
a window. PoLE = Proof of Living ENTROPY: unpredictable, unreproducible signal from the real
environment right now (a living body is a dense source, but so is the ambient world — not
anthropocentric). A receipt attests "a live-entropy source behind this persona was present over
[start,end], corroborated by these independent streams", WITHOUT revealing which. Un-fakeable because
live entropy from a place-time can't be pre-computed or replayed. Backs UBI eligibility + paid-
attention redemption.

Corroboration, not one reading (the lava-WALL, not one lamp): a receipt carries one or more signers
— the persona plus optional independent co-signers (the wearable, the Secure Enclave / App Attest).
`verify_receipt(..., min_signers=2)` requires >= 2 independent streams to agree, which is where a
moderate multi-stream reading crosses the presence bar that a single reading can't. The raw signals
never appear — only a `pole_commit` (a commitment to the fused evidence).

Reference of record. Swift parity: ios/AtlasCore/Sources/AtlasCore/Economy/PresenceReceipt.swift.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence, Tuple

from ..crypto.primitives import H
from ..crypto.sign import HybridSigKeypair, HybridSigPublic, sign, verify

_RECEIPT = b"atlas/presence-receipt/v1"


def _lp(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


def _be8(n: int) -> bytes:
    return int(n).to_bytes(8, "big")


@dataclass(frozen=True)
class PresenceReceipt:
    """A signed proof of presence. `signers` are the public keys that attest (persona + optional
    independent co-signers); `sigs[i]` is `signers[i]`'s signature over the body."""
    subject: bytes                          # the persona handle the presence is bound to
    window_start: int                       # beacon round / timestamp
    window_end: int
    pole_commit: bytes                      # commitment to the fused multi-stream evidence (no raw signals)
    signers: Tuple[HybridSigPublic, ...]
    sigs: Tuple[bytes, ...]

    def body(self) -> bytes:
        encs = sorted(s.encode() for s in self.signers)
        parts = [_RECEIPT, _lp(self.subject), _be8(self.window_start), _be8(self.window_end),
                 _lp(self.pole_commit), len(encs).to_bytes(4, "big")]
        parts.extend(_lp(e) for e in encs)
        return b"".join(parts)

    def id(self) -> bytes:
        return H(b"atlas/presence-receipt-id", self.body())

    def covers(self, *, at: int) -> bool:
        return self.window_start <= at <= self.window_end


def mint_receipt(signers: Sequence[HybridSigKeypair], *, subject: bytes, window_start: int,
                 window_end: int, pole_commit: bytes) -> PresenceReceipt:
    """Mint a presence receipt co-signed by each keypair (persona + any independent live streams)."""
    if window_end < window_start:
        raise ValueError("window_end < window_start")
    pubs = tuple(kp.public for kp in signers)
    # body is fixed by the SET of signers (sorted), so every co-signer signs the same bytes.
    tmp = PresenceReceipt(subject=subject, window_start=window_start, window_end=window_end,
                          pole_commit=pole_commit, signers=pubs, sigs=())
    body = tmp.body()
    sigs = tuple(sign(kp, body) for kp in signers)
    return PresenceReceipt(subject=subject, window_start=window_start, window_end=window_end,
                           pole_commit=pole_commit, signers=pubs, sigs=sigs)


def verify_receipt(r: PresenceReceipt, *, min_signers: int = 1) -> bool:
    """Valid iff at least `min_signers` DISTINCT signers each produced a valid signature over the
    body. `min_signers >= 2` enforces multi-stream corroboration (independent streams must agree)."""
    if len(r.signers) != len(r.sigs) or not r.signers:
        return False
    body = r.body()
    seen: set[bytes] = set()
    for pub, sig in zip(r.signers, r.sigs):
        enc = pub.encode()
        if enc not in seen and verify(pub, body, sig):
            seen.add(enc)
    return len(seen) >= min_signers


class ReceiptWallet:
    """A persona's collection of presence receipts — the PoLE receipts wallet."""

    def __init__(self) -> None:
        self._receipts: dict[bytes, PresenceReceipt] = {}   # id -> receipt (dedup)

    def add(self, r: PresenceReceipt, *, min_signers: int = 1) -> bool:
        if not verify_receipt(r, min_signers=min_signers):
            return False
        self._receipts[r.id()] = r
        return True

    @property
    def receipts(self) -> List[PresenceReceipt]:
        return list(self._receipts.values())

    def covering(self, *, at: int, min_signers: int = 1) -> List[PresenceReceipt]:
        """Receipts that attest presence at round/time `at` (used to back a redemption)."""
        return [r for r in self._receipts.values()
                if r.covers(at=at) and verify_receipt(r, min_signers=min_signers)]

    def total_presence(self) -> int:
        """Total attested presence duration across (non-overlapping-assumed) receipts."""
        return sum(max(0, r.window_end - r.window_start) for r in self._receipts.values())
