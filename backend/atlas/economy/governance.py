"""Governed index — who sets `col_index` / `value_index` for the issuance engine.

Not the company, not a single oracle: a VOTE of CERTIFIED NON-PROFITS (the journalism/organization
layer), anchored to public global references (IMF PPP/ICP, World Bank, OECD/IMF inflation). The
ratified value is the MEDIAN of the votes — robust to a captured or mistaken voter — and requires a
quorum. One vote per certified body (Sybil-free; certified bodies + verified-human keeps it
uncapturable). Decentralised value-setting is also the securities-positive move: no single promoter
decides value.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Set, Tuple


class QuorumError(Exception):
    """Not enough certified voters to ratify an index this epoch."""


@dataclass(frozen=True)
class IndexVote:
    voter: str      # a certified non-profit's id
    epoch: int
    col: int        # proposed cost-of-living index
    value: int      # proposed token value index (bp of par)


def _median(xs: Sequence[int]) -> int:
    s = sorted(xs)
    n = len(s)
    mid = n // 2
    return s[mid] if n % 2 else (s[mid - 1] + s[mid]) // 2


@dataclass
class IndexGovernance:
    """Registry of certified non-profit voters + the ratification rule."""
    quorum: int = 3
    _certified: Set[str] = field(default_factory=set)

    def certify(self, voter: str) -> None:
        self._certified.add(voter)

    def revoke(self, voter: str) -> None:
        self._certified.discard(voter)

    def is_certified(self, voter: str) -> bool:
        return voter in self._certified

    def ratify(self, votes: Sequence[IndexVote], *, epoch: int) -> Tuple[int, int]:
        """Return the ratified (col_index, value_index) for `epoch`: the median across certified
        voters (one vote each — last submission wins). Raises if the quorum isn't met."""
        valid: Dict[str, IndexVote] = {}
        for v in votes:
            if v.epoch == epoch and v.voter in self._certified:
                valid[v.voter] = v          # dedupe: one vote per certified body
        if len(valid) < self.quorum:
            raise QuorumError(f"need {self.quorum} certified voters, got {len(valid)}")
        cols: List[int] = [v.col for v in valid.values()]
        vals: List[int] = [v.value for v in valid.values()]
        return _median(cols), _median(vals)
