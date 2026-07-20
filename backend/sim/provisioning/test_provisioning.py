"""Property tests for the three provisioning primitives (integration / full stack).

Run:  cd backend && PYTHONPATH=. <simvenv>/bin/python -m sim.provisioning.test_provisioning
"""
from __future__ import annotations

from atlas.crypto import sign
from sim.provisioning import integration as prov
from sim.zk_personhood import personhood as zk
from sim.reshare import reshare as _rs_pkg  # ensure namespace import path is fine

results = []
def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))


def test_add_account():
    reg = zk.VerifiedHumanRegistry()
    a1 = prov.add_account(reg, k=2, tier=1)
    a2 = prov.add_account(reg, k=2, tier=2)

    # 1. genesis split + still functional after computer wipe (k factors reconstruct)
    from sim.pq_root import model as pqr
    part = {n: a1.holders[n] for n in list(a1.holders)[:a1.record.k]}
    seed_back = pqr.reconstruct_seed(a1.record, part)
    check("add_account: k-of-n split reconstructs after computer wipe", seed_back == a1._oracle_seed)
    check("add_account: computer holds nothing durable (record has no seed)",
          not hasattr(a1.record, "seed"))

    # 2. tiers map to assurance level
    check("add_account: tier1 -> level 1", a1.enrollment.level == 1)
    check("add_account: tier2 -> level 2 (Real-ID)", a2.enrollment.level == 2)

    # 3. anonymous personhood proof verifies
    w = reg.witness_for(a1.enrollment)
    proof = zk.prove(witness=w, root=reg.root, context=b"reddit", required_level=1)
    check("add_account: personhood proof verifies (anonymous, verified-human)",
          zk.verify_statement(proof))
    # per-context nullifier: same in-context, different cross-context, hides system_id
    n_reddit = zk.nullifier(a1.system_id, b"reddit")
    n_bank = zk.nullifier(a1.system_id, b"bank")
    check("add_account: nullifier deterministic per context (same-human handle)",
          zk.nullifier(a1.system_id, b"reddit") == n_reddit)
    check("add_account: cross-context nullifiers differ (unlinkable)", n_reddit != n_bank)
    check("add_account: public nullifier does not expose system_id",
          a1.system_id not in n_reddit)
    return a1


def test_add_node(a):
    old_share_e0 = next(iter(a.committee.values()))     # keep an epoch-0 share
    before = len(a.committee)
    new_x = prov.add_node(a, "server_node_2")
    check("add_node: committee grew by one", len(a.committee) == before + 1)
    check("add_node: epoch advanced", all(s.epoch == 1 for s in a.committee.values()))

    # same secret preserved (reconstruct any k of the NEW committee)
    from sim.reshare import reshare as rs
    k = a.record.k
    some_k = list(a.committee.values())[:k]
    seed_new = rs.epoch_combine(some_k)
    check("add_node: new committee reconstructs the SAME root seed", seed_new == a._oracle_seed)
    check("add_node: root public key unchanged (no re-root)",
          sign.sphincs_keypair_from_seed(seed_new).pk == a.record.root_pk)

    # old-epoch share cannot combine with new-epoch shares
    mixed_rejected = False
    try:
        rs.epoch_combine([old_share_e0, a.committee[new_x]])
    except ValueError:
        mixed_rejected = True
    check("add_node: old-epoch share cannot combine with new committee (epoch guard)", mixed_rejected)


def test_add_device(a):
    before = len(a.committee)
    new_x, dev_kp, cert = prov.add_device(a, "phone_2")
    check("add_device: committee grew by one (device is a shareholder)", len(a.committee) == before + 1)

    from sim.reshare import reshare as rs
    k = a.record.k
    seed_new = rs.epoch_combine(list(a.committee.values())[:k])
    check("add_device: same root seed preserved through device join", seed_new == a._oracle_seed)

    # device self-generated its own signer, distinct from the root
    check("add_device: device key is self-generated & distinct from root", dev_kp.pk != a.record.root_pk)

    # root certificate over the device pubkey verifies; tamper fails
    msg = b"atlas/device-cert|phone_2|" + dev_kp.pk
    check("add_device: root certifies device pubkey (cert verifies)",
          sign.sphincs_verify(a.record.root_pk, msg, cert))
    check("add_device: tampered device cert is rejected",
          not sign.sphincs_verify(a.record.root_pk, b"atlas/device-cert|EVIL|" + dev_kp.pk, cert))


if __name__ == "__main__":
    print("=" * 66)
    print("PROVISIONING INTEGRATION — add_account / add_node / add_device")
    print("=" * 66)
    acct = test_add_account()
    test_add_node(acct)
    test_add_device(acct)
    print("-" * 66)
    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"RESULT: {passed}/{total} checks PASS")
    raise SystemExit(0 if passed == total else 1)
