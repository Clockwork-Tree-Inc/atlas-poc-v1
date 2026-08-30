"""Anchor the PUBLIC economics to the accountability log.

The public monetary FACTS — per-epoch issuance, the business-transparency head, and governance
ratifications — are published as ROOTS through a `LedgerBackend` (local now, PoLE-consensus chain
later). These are meant to be public (no dark money, verifiable supply/rules). What is NOT anchored
here: individual balances and transfers — those stay private via per-person commitment ledgers
(`ledger.IndividualLedger`). Only roots are published, so even the public anchors reveal facts, not
people.
"""
from __future__ import annotations

import hashlib

from ..ledger.backend import LedgerBackend
from ..ledger.global_anchor import GlobalReceipt
from .policy import IssuanceResult
from .transparency import TransparencyLedger

# Distinct public streams on the accountability log.
ECONOMY_SUPPLY = b"atlas/economy/supply"
ECONOMY_TRANSPARENCY = b"atlas/economy/transparency"
ECONOMY_GOVERNANCE = b"atlas/economy/governance"


def _root(*parts: bytes) -> bytes:
    m = hashlib.sha3_256()
    for p in parts:
        m.update(len(p).to_bytes(4, "big"))
        m.update(p)
    return m.digest()


def _i(n: int) -> bytes:
    return int(n).to_bytes(16, "big")


def issuance_root(r: IssuanceResult) -> bytes:
    """A public commitment to one epoch's issuance facts (supply, minted, UBI/VRP/Foundation,
    tithe, controls) — a hash, so the fact is checkpointed without exposing per-account balances."""
    return _root(b"issuance", _i(r.epoch), _i(r.persons), _i(r.ubi_per_person), _i(r.ubi_total),
                 _i(r.vrp_total), _i(r.foundation_total), _i(r.tithe_used), _i(r.minted),
                 _i(r.new_supply), "|".join(r.controls).encode())


def anchor_issuance(backend: LedgerBackend, r: IssuanceResult, *, epoch_round: bytes) -> GlobalReceipt:
    return backend.publish(ECONOMY_SUPPLY, issuance_root(r), epoch_round)


def anchor_transparency(backend: LedgerBackend, ledger: TransparencyLedger, *,
                        epoch_round: bytes) -> GlobalReceipt:
    """Anchor the business-books head — immutably checkpoints all business activity to date."""
    return backend.publish(ECONOMY_TRANSPARENCY, ledger.head(), epoch_round)


def governance_root(epoch: int, col_index: int, value_index: int) -> bytes:
    return _root(b"governance", _i(epoch), _i(col_index), _i(value_index))


def anchor_governance(backend: LedgerBackend, *, epoch: int, col_index: int, value_index: int,
                      epoch_round: bytes) -> GlobalReceipt:
    return backend.publish(ECONOMY_GOVERNANCE, governance_root(epoch, col_index, value_index),
                           epoch_round)
