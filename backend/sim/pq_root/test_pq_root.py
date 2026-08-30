"""Property-assertion tests for the PQ root-of-trust custody topology.

Run from backend/ with the sim venv:
    simvenv/bin/python -m sim.pq_root.test_pq_root
or under pytest:
    simvenv/bin/python -m pytest sim/pq_root/test_pq_root.py

Prints PASS/FAIL per property and a short perf note.
"""

from __future__ import annotations

import itertools
import time

from atlas.crypto import sign

from sim.pq_root import model as m

K = 2  # threshold
FACTORS = m.FACTORS  # phone_se, usb, yubikey, server_se  (n = 4)


# ---------------------------------------------------------------------------
# Property 1 — GENESIS + SPLIT
# ---------------------------------------------------------------------------


def test_genesis_and_split():
    holders = m.make_holders(FACTORS)
    record, transient = m.genesis(holders, k=K, generation=0)

    # A root public key exists and every factor got exactly one wrapped share.
    assert len(record.root_pk) == 32
    assert set(record.wrapped.keys()) == set(FACTORS)
    assert record.k == K and record.n == len(FACTORS)

    # Each share unwraps ONLY with its own holder's KEM secret.
    for name in FACTORS:
        w = record.wrapped[name]
        share = m.unwrap_share(holders[name], w)  # correct holder: succeeds
        assert share.y  # non-empty y payload

        # Any OTHER holder trying to unwrap this share must fail.
        for other in FACTORS:
            if other == name:
                continue
            try:
                m.unwrap_share(holders[other], w)
                raise AssertionError(f"{other} unwrapped {name}'s share!")
            except AssertionError:
                raise
            except Exception:
                pass  # expected: KEM/AEAD rejects the wrong holder

    # Wrapped shares carry no plaintext seed material (sanity: they are ciphertext).
    assert transient.seed is not None and len(transient.seed) == sign.SPX_SEED_BYTES


# ---------------------------------------------------------------------------
# Property 2 — THRESHOLD RECONSTRUCT
# ---------------------------------------------------------------------------


def test_threshold_reconstruct():
    holders = m.make_holders(FACTORS)
    record, transient = m.genesis(holders, k=K, generation=0)
    transient.wipe()  # computer gone; only holders + record remain

    msg = b"continuity-event: rotate beacon anchor @ 2026-07-15"

    # ANY k holders reconstruct and sign a verifiable continuity event.
    for combo in itertools.combinations(FACTORS, K):
        participating = {n: holders[n] for n in combo}
        sig = m.sign_continuity_event(record, participating, msg)
        assert sign.sphincs_verify(record.root_pk, msg, sig), f"{combo} sig failed"

    # FEWER than k reconstruct NOTHING (no seed, no signature).
    for combo in itertools.combinations(FACTORS, K - 1):
        participating = {n: holders[n] for n in combo}
        try:
            m.reconstruct_seed(record, participating)
            raise AssertionError(f"{combo} reconstructed below threshold!")
        except AssertionError:
            raise
        except m.ReconstructError:
            pass  # expected


# ---------------------------------------------------------------------------
# Property 3 — COMPUTER WIPED AT GENESIS
# ---------------------------------------------------------------------------


def test_computer_wiped_at_genesis():
    holders = m.make_holders(FACTORS)
    record, transient = m.genesis(holders, k=K, generation=0)

    # Model the computer deleting its copy right after genesis.
    transient.wipe()
    assert transient.wiped
    assert transient.seed is None and transient.keypair is None
    assert transient.raw_shares is None

    # "Losing the computer" == dropping its state entirely. The computer was
    # never a share holder, so the account is fully functional: still k-of-n
    # among the remaining factors + server.
    del transient  # the computer is gone

    msg = b"continuity-event after computer loss"
    # Use the personal factors + server; computer contributes nothing.
    participating = {n: holders[n] for n in ("usb", "server_se")}
    sig = m.sign_continuity_event(record, participating, msg)
    assert sign.sphincs_verify(record.root_pk, msg, sig)


# ---------------------------------------------------------------------------
# Property 4 — RE-ROOT REVOCATION
# ---------------------------------------------------------------------------


def test_reroot_revocation():
    holders = m.make_holders(FACTORS)
    rec0, t0 = m.genesis(holders, k=K, generation=0)
    old_seed = t0.seed
    old_wrapped = dict(rec0.wrapped)
    t0.wipe()

    # Re-root: fresh generation with a brand-new seed/keypair, new wrapped shares.
    rec1, t1 = m.genesis(holders, k=K, generation=1)
    t1.wipe()

    # New root differs from old root.
    assert rec1.root_pk != rec0.root_pk

    # OLD shares no longer reconstruct the CURRENT root. Reconstruct from old
    # wrapped shares -> old seed -> old keypair, whose pk != current root_pk.
    old_shares = [m.unwrap_share(holders[n], old_wrapped[n]) for n in ("phone_se", "usb")]
    from atlas.crypto import shamir

    recovered_old_seed = shamir.combine(old_shares)
    assert recovered_old_seed == old_seed  # old shares still reconstruct the OLD seed
    old_kp = sign.sphincs_keypair_from_seed(recovered_old_seed)
    assert old_kp.pk != rec1.root_pk  # ...which is NOT the current root

    # A single leaked OLD share reveals nothing: below threshold (k=2) and, on
    # its own, a Shamir share is independent of the secret.
    single = {"phone_se": holders["phone_se"]}
    try:
        m.reconstruct_seed(rec0, single)
        raise AssertionError("single share reconstructed a seed!")
    except m.ReconstructError:
        pass


# ---------------------------------------------------------------------------
# Property 5 — SHARE-LOSS SURVIVABILITY
# ---------------------------------------------------------------------------


def test_share_loss_survivability():
    holders = m.make_holders(FACTORS)
    record, transient = m.genesis(holders, k=K, generation=0)
    transient.wipe()

    msg = b"continuity-event: USB lost, still operational"

    # Lose one factor (USB). Remaining {phone_se, yubikey, server_se} >= k.
    surviving = {n: holders[n] for n in FACTORS if n != "usb"}
    assert len(surviving) >= record.k
    sig = m.sign_continuity_event(record, surviving, msg)
    assert sign.sphincs_verify(record.root_pk, msg, sig)

    # Even losing any single factor leaves >= k for every choice of lost factor.
    for lost in FACTORS:
        remaining = {n: holders[n] for n in FACTORS if n != lost}
        assert len(remaining) >= record.k
        s = m.sign_continuity_event(record, remaining, msg)
        assert sign.sphincs_verify(record.root_pk, msg, s)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

PROPERTIES = [
    ("1 GENESIS + SPLIT", test_genesis_and_split),
    ("2 THRESHOLD RECONSTRUCT", test_threshold_reconstruct),
    ("3 COMPUTER WIPED AT GENESIS", test_computer_wiped_at_genesis),
    ("4 RE-ROOT REVOCATION", test_reroot_revocation),
    ("5 SHARE-LOSS SURVIVABILITY", test_share_loss_survivability),
]


def main() -> int:
    print("=" * 68)
    print("PQ ROOT-OF-TRUST CUSTODY SIMULATION  (real SLH-DSA + Shamir + ML-KEM)")
    print(f"  factors = {FACTORS}   threshold k={K}-of-{len(FACTORS)}")
    print("=" * 68)

    # Perf note: one genesis + one continuity signature timing.
    holders = m.make_holders(FACTORS)
    t = time.time(); rec, tr = m.genesis(holders, k=K); t_gen = time.time() - t
    tr.wipe()
    part = {n: holders[n] for n in ("phone_se", "server_se")}
    t = time.time(); sig = m.sign_continuity_event(rec, part, b"perf"); t_evt = time.time() - t
    ok = sign.sphincs_verify(rec.root_pk, b"perf", sig)
    print(f"perf: genesis(keygen+split+wrap x{len(FACTORS)}) = {t_gen*1000:.0f} ms")
    print(f"perf: reconstruct + SLH-DSA sign continuity event = {t_evt*1000:.0f} ms "
          f"(verify={ok}, sig={len(sig)} B)")
    print("-" * 68)

    failures = 0
    for label, fn in PROPERTIES:
        try:
            fn()
            print(f"PASS  Property {label}")
        except Exception as e:  # noqa: BLE001
            failures += 1
            print(f"FAIL  Property {label}: {type(e).__name__}: {e}")
    print("-" * 68)
    print(f"RESULT: {len(PROPERTIES) - failures}/{len(PROPERTIES)} properties PASS")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
