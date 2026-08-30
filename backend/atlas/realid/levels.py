"""Graduated assurance levels (Real-ID spec §3)."""

from __future__ import annotations

from enum import IntEnum


class AssuranceLevel(IntEnum):
    """A context requests the minimum it needs.

    L0 — verified live human (presence only); no real-ID involved.
    L1 — backed by a verified real-world identity (inherited status); ID NOT
         revealed. Private accountability — the common case.
    L2 — specific legal identity disclosed (real-ID child surfaced); explicit
         consent, logged. The high-exposure case.
    """

    L0 = 0
    L1 = 1
    L2 = 2
