"""Social reactions over Space content — votes (like/dislike, Reddit-style), and reports (flag for
moderation). Token-free trust primitives: signed statements by verified humans over a content item.

Not new crypto — HybridSig signatures over domain-separated, length-prefixed bodies (same discipline
as the authority engine and the market).

ONE-HUMAN-ONE-VOTE. A vote carries a `nullifier` — an opaque, per-target, per-HUMAN tag that resolves
to the personhood/PoLE layer (cf. `realid/space_pseudonym.space_nullifier`). The tally dedupes by
nullifier, so a single human can't inflate a score by voting from many pseudonyms, yet CAN change
their own vote (last cast wins). Without the personhood layer the nullifier is caller-supplied here
(the interface is the contract); with it, it's unforgeable and unlinkable across targets.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Sequence

from ..crypto.sign import HybridSigKeypair, HybridSigPublic, sign, verify

_VOTE_DOMAIN = b"atlas/social/vote/v1"
_REPORT_DOMAIN = b"atlas/social/report/v1"

LIKE = 1
DISLIKE = -1


def _lp(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


# --------------------------------------------------------------------------- votes (like / dislike)
@dataclass
class Vote:
    """A signed like (+1) or dislike (-1) by `voter` over `target` (a content_hash). `nullifier`
    enforces one-human-one-vote at tally time (dedupe key); `voter` is the persona that cast it."""

    voter: HybridSigPublic
    target: bytes
    value: int            # +1 LIKE or -1 DISLIKE
    nullifier: bytes
    epoch: int
    sig: bytes = b""

    def _body(self) -> bytes:
        return b"".join([_VOTE_DOMAIN, _lp(self.voter.encode()), _lp(self.target),
                         (b"\x01" if self.value >= 0 else b"\xff"), _lp(self.nullifier),
                         self.epoch.to_bytes(8, "big")])


def cast_vote(kp: HybridSigKeypair, *, target: bytes, value: int, nullifier: bytes,
              epoch: int) -> Vote:
    if value not in (LIKE, DISLIKE):
        raise ValueError("vote value must be +1 (like) or -1 (dislike)")
    v = Vote(voter=kp.public, target=target, value=value, nullifier=nullifier, epoch=epoch)
    v.sig = sign(kp, v._body())
    return v


def verify_vote(v: Vote) -> bool:
    return v.value in (LIKE, DISLIKE) and verify(v.voter, v._body(), v.sig)


@dataclass(frozen=True)
class Score:
    target: bytes
    likes: int
    dislikes: int

    @property
    def net(self) -> int:
        return self.likes - self.dislikes


def tally(target: bytes, votes: Sequence[Vote]) -> Score:
    """Reddit-style score for `target`. Only VALID votes for THIS target count; one-human-one-vote via
    nullifier dedup (LAST cast wins, so re-voting flips your like↔dislike instead of stacking)."""
    latest: Dict[bytes, Vote] = {}
    for v in votes:
        if v.target == target and verify_vote(v):
            latest[v.nullifier] = v                  # last valid vote per human wins
    likes = sum(1 for v in latest.values() if v.value == LIKE)
    dislikes = sum(1 for v in latest.values() if v.value == DISLIKE)
    return Score(target=target, likes=likes, dislikes=dislikes)


# --------------------------------------------------------------------------- reports (flag for mods)
@dataclass
class Report:
    """A signed flag on `target` (a content_hash) for moderator review. Reason is a short code/string
    (e.g. 'spam', 'harm', 'abuse'). Reports FEED moderation — a MODERATOR+ acts via SpaceStore.ban /
    content removal; a report by itself removes nothing (no heckler's veto)."""

    reporter: HybridSigPublic
    target: bytes
    reason: str
    epoch: int
    sig: bytes = b""

    def _body(self) -> bytes:
        return b"".join([_REPORT_DOMAIN, _lp(self.reporter.encode()), _lp(self.target),
                         _lp(self.reason.encode()), self.epoch.to_bytes(8, "big")])


def file_report(kp: HybridSigKeypair, *, target: bytes, reason: str, epoch: int) -> Report:
    r = Report(reporter=kp.public, target=target, reason=reason, epoch=epoch)
    r.sig = sign(kp, r._body())
    return r


def verify_report(r: Report) -> bool:
    return verify(r.reporter, r._body(), r.sig)


def report_counts(reports: Sequence[Report]) -> Dict[bytes, int]:
    """Distinct-reporter counts per target (a queue signal for moderators). Dedupes multiple reports
    from the same reporter on the same target so one persona can't manufacture a pile-on."""
    seen: Dict[bytes, set] = {}
    for r in reports:
        if verify_report(r):
            seen.setdefault(r.target, set()).add(r.reporter.encode())
    return {target: len(reporters) for target, reporters in seen.items()}
