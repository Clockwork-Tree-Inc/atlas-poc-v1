"""Soul-bound tokens (SBTs) — non-transferable participation credentials.

A soul-bound token is a credential CRYPTOGRAPHICALLY BOUND to a holder's identity (their "soul"). It
cannot be transferred, sold, or reassigned — the holder's key is baked into the signed body, so moving
it to another holder invalidates it. It carries NO monetary value, no mint-from-capital, and no
cash-out path: it is a proof of participation/presence you COLLECT, not a coin you trade.

This is the participation on-ramp people can use now: each PoLE attestation (proof a live human was
present in an epoch) can be collected as a soul-bound token that accumulates in the holder's
collection. Turning participation into money is a SEPARATE, deferred, regulated concern — an SBT is a
badge, not a currency. Keeping it soul-bound + non-monetary is exactly what keeps it clear of the
financial-instrument line.

Not new crypto — HybridSig signatures over domain-separated, length-prefixed bodies.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from ..crypto.primitives import H
from ..crypto.sign import HybridSigKeypair, HybridSigPublic, sign, verify

_SBT_DOMAIN = b"atlas/sbt/v1"

# The token kind for a PoLE "I was a present, living human this epoch" participation proof.
PARTICIPATION = b"atlas/sbt/participation"


def _lp(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


@dataclass
class SoulboundToken:
    """A non-transferable credential bound to `holder` (the soul). `issuer` signs it; for a
    self-collected participation proof, issuer == holder. No value field exists — it is not money."""

    holder: HybridSigPublic     # the soul this is permanently bound to
    kind: bytes                 # what it attests (e.g. PARTICIPATION, or an org badge)
    issuer: HybridSigPublic     # who issued it (== holder for self-collected participation)
    epoch: int
    payload: bytes = b""        # optional detail (e.g. a PoLE proof commitment)
    sig: bytes = b""

    def _body(self) -> bytes:
        return b"".join([_SBT_DOMAIN, _lp(self.holder.encode()), _lp(self.kind),
                         _lp(self.issuer.encode()), self.epoch.to_bytes(8, "big"), _lp(self.payload)])

    def token_id(self) -> bytes:
        """Stable id derived from the (holder, kind, issuer, epoch, payload) — binds the token to the
        soul; you cannot re-home it without producing a different, unsigned token."""
        return H(b"atlas/sbt-id", self._body())


def issue_sbt(issuer_kp: HybridSigKeypair, *, holder: HybridSigPublic, kind: bytes, epoch: int,
              payload: bytes = b"") -> SoulboundToken:
    """Issue a soul-bound token TO `holder` (e.g. an org awarding a badge). The holder is baked into
    the signed body, so it can never be transferred to another soul."""
    t = SoulboundToken(holder=holder, kind=kind, issuer=issuer_kp.public, epoch=epoch, payload=payload)
    t.sig = sign(issuer_kp, t._body())
    return t


def collect_participation(holder_kp: HybridSigKeypair, *, epoch: int,
                          pole_commitment: bytes = b"") -> SoulboundToken:
    """Self-collect a PARTICIPATION token for `epoch`, backed by a PoLE proof commitment. Issuer ==
    holder: you attest your own presence, provable by the PoLE commitment carried in the payload."""
    return issue_sbt(holder_kp, holder=holder_kp.public, kind=PARTICIPATION, epoch=epoch,
                     payload=pole_commitment)


def verify_sbt(t: SoulboundToken) -> bool:
    """Valid iff the issuer signed exactly this (holder, kind, issuer, epoch, payload)."""
    return verify(t.issuer, t._body(), t.sig)


class SoulboundCollection:
    """A holder's collection of soul-bound tokens. Enforces NON-TRANSFERABILITY structurally: it will
    ONLY hold tokens bound to THIS holder — you cannot receive, buy, or collect a token soul-bound to
    someone else. There is deliberately no `transfer` method anywhere."""

    def __init__(self, holder: HybridSigPublic) -> None:
        self.holder = holder
        self._by_id: Dict[bytes, SoulboundToken] = {}

    def add(self, t: SoulboundToken) -> bool:
        """Collect a token. Rejected (False) unless it VERIFIES and is bound to THIS holder — that
        holder check is the structural block on transfers (a token bound to another soul can't land
        here, and its holder can't be changed without breaking the signature)."""
        if not verify_sbt(t):
            return False
        if t.holder.encode() != self.holder.encode():
            return False
        self._by_id[t.token_id()] = t
        return True

    def balance(self, kind: Optional[bytes] = None) -> int:
        """How many distinct tokens the soul holds (of `kind`, if given). Participation is one-per-
        epoch: re-collecting the same epoch does not inflate the count."""
        toks = list(self._by_id.values())
        if kind is not None:
            toks = [t for t in toks if t.kind == kind]
        return len({(t.kind, t.epoch) for t in toks})

    def epochs(self, kind: bytes = PARTICIPATION) -> List[int]:
        """The epochs this soul has collected a token of `kind` for (sorted)."""
        return sorted({t.epoch for t in self._by_id.values() if t.kind == kind})
