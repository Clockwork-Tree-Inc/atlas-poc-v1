"""Integration / full-stack simulation: the three provisioning primitives.

Composes the VERIFIED foundation sims into the operable interface the design
targets: `add_account`, `add_node`, `add_device`. This is a pure-Python
REFERENCE MODEL (not production crypto). No existing atlas/ code is modified.

  add_account  = pq_root.genesis (split root across factors) + wipe computer
                 + register a verified-human commitment (zk_personhood)   [tiered]
  add_node     = reshare the root's shares to a committee that includes the new
                 node, WITHOUT reconstructing the secret
  add_device   = reshare (add the device as a shareholder) + the device
                 self-generates an SLH-DSA signer that the root certifies

A "sim oracle" retains the root seed OUT OF BAND purely so the test can assert
same-secret invariants; the modelled design itself never keeps it (the computer
is wiped). Oracle values are clearly named `_oracle_*`.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Dict, List

# foundation modules
from atlas.crypto import shamir, sign, primitives
from sim.pq_root import model as pqr
from sim.zk_personhood import personhood as zk

# reshare.py is imported as a top-level module (mirrors its own test harness)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "reshare"))
import reshare as rs  # noqa: E402


FACTORS = ["phone_se", "usb", "yubikey", "server_se"]  # durable holders (NOT the computer)


@dataclass
class Account:
    holders: Dict[str, pqr.Holder]
    record: pqr.GenerationRecord
    # committee as reshare EpochShares, keyed by x-coord (bridges pq_root <-> reshare)
    committee: Dict[int, rs.EpochShare]
    name_by_x: Dict[int, str]
    system_id: bytes
    enrollment: object
    tier: int
    _oracle_seed: bytes = field(repr=False)  # sim-only, for same-secret assertions


def _committee_from_record(record: pqr.GenerationRecord,
                           holders: Dict[str, pqr.Holder]) -> tuple[Dict[int, rs.EpochShare], Dict[int, str]]:
    """Bridge: unwrap every holder's share and tag it as an epoch-0 EpochShare,
    keyed by its Shamir x-coord. (Unwrapping all here is a sim convenience; in
    the real flow only the k participating holders unwrap, at reshare time.)"""
    committee: Dict[int, rs.EpochShare] = {}
    name_by_x: Dict[int, str] = {}
    for name, w in record.wrapped.items():
        sh = pqr.unwrap_share(holders[name], w)
        committee[sh.index] = rs.EpochShare(epoch=0, share=sh)
        name_by_x[sh.index] = name
    return committee, name_by_x


# --------------------------------------------------------------------------- add_account
def add_account(registry: zk.VerifiedHumanRegistry, *, k: int = 2, tier: int = 1) -> Account:
    """Enroll a user: PQ root genesis split across the durable factors, computer
    wiped, verified-human commitment registered. tier 1 = anonymous (level 1);
    tier 2 = Real-ID populated (level 2 + a legal-ID dedup anchor, modelled)."""
    holders = pqr.make_holders(FACTORS)
    record, transient = pqr.genesis(holders, k=k, generation=0)
    oracle_seed = transient.seed            # capture BEFORE wipe (sim oracle only)
    transient.wipe()                        # computer holds nothing durable

    system_id = primitives.random_bytes(32)
    level = 2 if tier == 2 else 1
    blind = primitives.random_bytes(16)
    enrollment = registry.register(system_id, level, blind)

    committee, name_by_x = _committee_from_record(record, holders)
    return Account(holders=holders, record=record, committee=committee, name_by_x=name_by_x,
                   system_id=system_id, enrollment=enrollment, tier=tier, _oracle_seed=oracle_seed)


# --------------------------------------------------------------------------- add_node
def add_node(acct: Account, node_name: str) -> int:
    """Add a server node to the threshold committee via re-sharing (no secret
    reconstruction). Returns the new node's x-coord."""
    old_shares = list(acct.committee.values())            # current committee (epoch e)
    k = acct.record.k
    participating = old_shares[:k]                         # >= k old holders cooperate
    new_x = max(acct.committee) + 1
    new_indices = sorted(list(acct.committee.keys()) + [new_x])
    new_committee = rs.reshare(participating, new_indices=new_indices, k_new=k)
    acct.committee = {s.index: s for s in new_committee}   # epoch e+1
    acct.name_by_x[new_x] = node_name
    return new_x


# --------------------------------------------------------------------------- add_device
def add_device(acct: Account, device_name: str) -> tuple[int, sign.SphincsKeypair, bytes]:
    """Add a device: (1) it self-generates its OWN SLH-DSA signer, (2) it joins
    the threshold committee via re-sharing, (3) the root certifies its pubkey.
    Returns (x-coord, device keypair, root's certificate over the device pk)."""
    # 1. Device self-generates (private half never leaves it).
    dev_seed = primitives.random_bytes(sign.SPX_SEED_BYTES)
    dev_kp = sign.sphincs_keypair_from_seed(dev_seed)

    # 2. Join the committee (same primitive as add_node).
    new_x = add_node(acct, device_name)

    # 3. Root certifies the device pubkey: transiently reconstruct the root and sign.
    #    (Reconstruct from k durable factors on the trusted computer, then wipe.)
    part = {name: acct.holders[name] for name in list(acct.holders)[: acct.record.k]}
    root_kp = pqr.reconstruct_keypair(acct.record, part)
    cert = sign.sphincs_sign(root_kp, b"atlas/device-cert|" + device_name.encode() + b"|" + dev_kp.pk)
    return new_x, dev_kp, cert
