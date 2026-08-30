"""Polls over Space content — Sybil-free polling at configurable anonymity levels.

A poll is a structured, multi-option vote. Its integrity rests on the same one-human-one-response
NULLIFIER as social votes (cf. realid/space_pseudonym), so a poll cannot be brigaded by bots or
sockpuppets — one enrolled human, one response, guaranteed. The ANONYMITY LEVEL is orthogonal to that
Sybil-resistance: it controls whether a ballot reveals the voter's persona, never whether one human
can stuff the box.

IdentityTier (the "various levels of anonymity"):
  * ANONYMOUS       — the ballot is signed by a FRESH EPHEMERAL key, unlinkable to any persona; only
                      the nullifier ties it to "one human" (and the personhood layer keeps that
                      nullifier unlinkable across polls). You learn the tally, never who chose what.
                      Eligibility (the nullifier belongs to an enrolled human) is proven in production
                      by an anonymous credential (realid/ps_credential); here that check is a seam.
  * PSEUDONYMOUS    — the ballot is signed by the voter's persona; the choice is visible under that nym.
  * VERIFIED_PERSON — like pseudonymous, but the nullifier is a PER-HUMAN tag (personhood-backed), so
                      one human = one response even across their pseudonyms. Accountable; real-ID hidden.

Not new crypto — HybridSig over domain-separated, length-prefixed bodies + nullifier dedup.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Sequence, Tuple

from ..crypto.primitives import H
from ..crypto.sign import HybridSigKeypair, HybridSigPublic, sign, verify
from .kinds import IdentityTier   # the canonical anonymity axis (shared with Spaces)

__all__ = ["IdentityTier", "Poll", "PollResponse", "PollResult", "create_poll", "verify_poll",
           "respond", "respond_anonymously", "verify_response", "tally"]

_POLL_DOMAIN = b"atlas/poll/v1"
_RESPONSE_DOMAIN = b"atlas/poll-response/v1"


def _lp(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


# --------------------------------------------------------------------------- poll
@dataclass
class Poll:
    author: HybridSigPublic
    question: bytes
    options: Tuple[bytes, ...]
    tier: IdentityTier
    epoch: int
    sig: bytes = b""

    def _body(self) -> bytes:
        parts = [_POLL_DOMAIN, _lp(self.author.encode()), _lp(self.question),
                 len(self.options).to_bytes(4, "big")]
        parts.extend(_lp(o) for o in self.options)
        parts.append(int(self.tier).to_bytes(2, "big"))
        parts.append(self.epoch.to_bytes(8, "big"))
        return b"".join(parts)

    def poll_id(self) -> bytes:
        """A stable id derived from the poll's content (author + question + options + tier + epoch)."""
        return H(b"atlas/poll-id", self._body())


def create_poll(kp: HybridSigKeypair, *, question: bytes, options: Sequence[bytes],
                tier: IdentityTier, epoch: int) -> Poll:
    if len(options) < 2:
        raise ValueError("a poll needs >= 2 options")
    p = Poll(author=kp.public, question=question, options=tuple(options), tier=tier, epoch=epoch)
    p.sig = sign(kp, p._body())
    return p


def verify_poll(p: Poll) -> bool:
    return len(p.options) >= 2 and verify(p.author, p._body(), p.sig)


# --------------------------------------------------------------------------- response (ballot)
@dataclass
class PollResponse:
    poll_id: bytes
    choice: int                    # index into poll.options
    nullifier: bytes               # one-human-one-response dedup key (from the personhood layer)
    ballot_key: HybridSigPublic    # voter persona (pseudonymous/verified) OR ephemeral (anonymous)
    epoch: int
    sig: bytes = b""

    def _body(self) -> bytes:
        return b"".join([_RESPONSE_DOMAIN, _lp(self.poll_id), self.choice.to_bytes(4, "big"),
                         _lp(self.nullifier), _lp(self.ballot_key.encode()),
                         self.epoch.to_bytes(8, "big")])


def _make_response(poll: Poll, choice: int, nullifier: bytes, ballot_key: HybridSigPublic,
                   epoch: int) -> PollResponse:
    if not (0 <= choice < len(poll.options)):
        raise ValueError("choice out of range")
    return PollResponse(poll_id=poll.poll_id(), choice=choice, nullifier=nullifier,
                        ballot_key=ballot_key, epoch=epoch)


def respond(voter_kp: HybridSigKeypair, poll: Poll, *, choice: int, nullifier: bytes,
            epoch: int) -> PollResponse:
    """A PSEUDONYMOUS / VERIFIED_PERSON ballot — signed by the voter's persona (the choice is visible
    under that nym). One-human-one-response via `nullifier`; for VERIFIED_PERSON the nullifier is a
    per-human tag, so it holds even across the voter's pseudonyms."""
    r = _make_response(poll, choice, nullifier, voter_kp.public, epoch)
    r.sig = sign(voter_kp, r._body())
    return r


def respond_anonymously(poll: Poll, *, choice: int, nullifier: bytes, epoch: int,
                        ephemeral_kp: HybridSigKeypair) -> PollResponse:
    """An ANONYMOUS ballot — signed by a FRESH EPHEMERAL key that is unlinkable to the voter's persona.
    The choice can never be tied back to a person; only the `nullifier` enforces one-human-one-response
    (unlinkable across polls, from the personhood layer). Eligibility — that this ballot is backed by an
    enrolled human — is proven by an anonymous credential (realid/ps_credential) in production."""
    r = _make_response(poll, choice, nullifier, ephemeral_kp.public, epoch)
    r.sig = sign(ephemeral_kp, r._body())
    return r


def verify_response(poll: Poll, r: PollResponse) -> bool:
    return (r.poll_id == poll.poll_id() and 0 <= r.choice < len(poll.options)
            and verify(r.ballot_key, r._body(), r.sig))


# --------------------------------------------------------------------------- tally
@dataclass(frozen=True)
class PollResult:
    poll_id: bytes
    counts: Tuple[int, ...]   # votes per option, aligned to poll.options
    total: int                # distinct humans who responded

    def winner(self) -> int:
        """Index of the leading option (first, on a tie)."""
        return max(range(len(self.counts)), key=lambda i: self.counts[i]) if self.counts else -1


def tally(poll: Poll, responses: Sequence[PollResponse]) -> PollResult:
    """One-human-one-response: dedupe by `nullifier` (LAST valid response wins, so a voter can change
    their choice — it flips, never stacks). Only valid responses FOR THIS poll count."""
    latest: Dict[bytes, PollResponse] = {}
    for r in responses:
        if verify_response(poll, r):
            latest[r.nullifier] = r
    counts = [0] * len(poll.options)
    for r in latest.values():
        counts[r.choice] += 1
    return PollResult(poll_id=poll.poll_id(), counts=tuple(counts), total=len(latest))
