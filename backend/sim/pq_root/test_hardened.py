"""Property-assertion tests for the HARDENED PQ root-of-trust custody model.

Run from backend/ with the sim venv:
    simvenv/bin/python -m sim.pq_root.test_hardened

Prints PASS/FAIL per property; exits 0 iff ALL pass.

Covers the three hardening closes plus a re-confirmation of the base properties:
  1  k TUNING              — n=5, k=3: any 2 fail, any 3 succeed (no 2-way collusion)
  2  SHARE AUTHENTICATION  — tampered share DETECTED and holder ATTRIBUTED
  3  EXPLICIT ZEROIZATION  — seed/share buffers provably all-zero after wipe()
  4  THRESHOLD + CONTINUITY SIGN — reconstruct + SLH-DSA sign still verifies
  5  COMPUTER WIPED AT GENESIS
  6  RE-ROOT REVOCATION
"""

from __future__ import annotations

import itertools
import time

from atlas.crypto import shamir, sign

from sim.pq_root import hardened as h
from sim.pq_root import model as m

FACTORS = h.HARDENED_FACTORS  # 5 durable holders
N = len(FACTORS)
K = h.default_threshold(N)  # == 3 for n=5


# ---------------------------------------------------------------------------
# CLOSE 1 — k TUNING: any 2 fail, any 3 succeed (no two holders collude)
# ---------------------------------------------------------------------------


def test_k_tuning_collusion_resistant():
    assert N == 5 and K == 3, f"expected n=5 k=3, got n={N} k={K}"

    holders = m.make_holders(FACTORS)
    record, transient = h.genesis(holders, generation=0)
    assert record.k == 3 and record.n == 5
    transient.wipe()

    msg = b"continuity-event: k-tuning"

    # ANY 2 holders (every pair) must FAIL to reconstruct -> no 2-way collusion.
    for combo in itertools.combinations(FACTORS, 2):
        participating = {n: holders[n] for n in combo}
        try:
            h.reconstruct_seed(record, participating)
            raise AssertionError(f"2 holders {combo} reconstructed the seed!")
        except AssertionError:
            raise
        except m.ReconstructError:
            pass  # expected: below threshold

    # ANY 3 holders (every triple) must SUCCEED and produce a valid signature.
    triples = list(itertools.combinations(FACTORS, 3))
    for combo in triples:
        participating = {n: holders[n] for n in combo}
        sig = h.sign_continuity_event(record, participating, msg)
        assert sign.sphincs_verify(record.root_pk, msg, sig), f"{combo} sig failed"

    # default_threshold stays collusion-resistant across committee sizes.
    for n in range(3, 12):
        assert h.default_threshold(n) >= 3


# ---------------------------------------------------------------------------
# CLOSE 2 — SHARE AUTHENTICATION: tampered share detected AND attributed
# ---------------------------------------------------------------------------


def test_share_authentication_detects_and_attributes():
    holders = m.make_holders(FACTORS)
    record, transient = h.genesis(holders, generation=0)
    transient.wipe()

    # Genesis published one commitment per holder.
    assert set(record.commitments) == set(FACTORS)

    # Honest shares all verify.
    for name in FACTORS:
        share = m.unwrap_share(holders[name], record.wrapped[name])
        assert h.verify_share(record, name, share), f"{name} honest share rejected"

    # Model a MALICIOUS holder handing a tampered share into reconstruction.
    victim = "yubikey"
    bad_share = h.corrupt_holder_share(record, holders[victim])
    assert not h.verify_share(record, victim, bad_share), "tamper not detected"

    # A reconstruction that includes the corrupted holder must RAISE and NAME it.
    # Wire the bad share in by swapping the holder's wrapped share for a tampered
    # one so reconstruct_seed unwraps garbage and the commitment check fires.
    tampered_wrapped = dict(record.wrapped)
    # Re-wrap the tampered share to the victim so it unwraps (auth is post-unwrap).
    tampered_wrapped[victim] = m.wrap_share_to(
        holders[victim], record.generation, bad_share
    )
    tampered_record = h.HardenedGenerationRecord(
        generation=record.generation,
        root_pk=record.root_pk,
        wrapped=tampered_wrapped,
        commitments=record.commitments,
        k=record.k,
        n=record.n,
    )

    participating = {n: holders[n] for n in ("phone_se", "usb", victim)}
    try:
        h.reconstruct_seed(tampered_record, participating)
        raise AssertionError("tampered share silently accepted!")
    except h.ShareAuthError as e:
        assert e.holder == victim, f"wrong holder attributed: {e.holder}"

    # With the bad holder replaced by an honest one, reconstruction succeeds:
    # the corrupt holder is isolated, the account still operates.
    healthy = {n: holders[n] for n in ("phone_se", "usb", "server1_se")}
    seed = h.reconstruct_seed(tampered_record, healthy)
    kp = sign.sphincs_keypair_from_seed(seed)
    assert kp.pk == record.root_pk


# ---------------------------------------------------------------------------
# CLOSE 3 — EXPLICIT ZEROIZATION: buffers provably zeroed after wipe()
# ---------------------------------------------------------------------------


def test_explicit_zeroization():
    holders = m.make_holders(FACTORS)
    record, transient = h.genesis(holders, generation=0)

    # Grab references to the ACTUAL buffers before wiping.
    seed_buf = transient.seed
    share_bufs = list(transient.raw_shares)
    assert isinstance(seed_buf, bytearray) and len(seed_buf) == sign.SPX_SEED_BYTES
    assert any(b != 0 for b in seed_buf), "seed was already zero before wipe (bogus)"
    assert all(len(sb) > 0 for sb in share_bufs)

    transient.wipe()

    # The transient dropped its references...
    assert transient.wiped
    assert transient.seed is None and transient.raw_shares is None
    assert transient.keypair is None

    # ...AND the underlying memory we still hold a handle to is ALL ZERO, i.e.
    # the bytes were overwritten in place, not merely dereferenced.
    assert all(b == 0 for b in seed_buf), "seed buffer not zeroed in place"
    for sb in share_bufs:
        assert all(b == 0 for b in sb), "share buffer not zeroed in place"


# ---------------------------------------------------------------------------
# RE-CONFIRM 4 — THRESHOLD RECONSTRUCT + SLH-DSA CONTINUITY SIGN
# ---------------------------------------------------------------------------


def test_threshold_and_continuity_sign():
    holders = m.make_holders(FACTORS)
    record, transient = h.genesis(holders, generation=0)
    transient.wipe()

    msg = b"continuity-event: rotate beacon anchor (hardened)"
    participating = {n: holders[n] for n in ("phone_se", "server1_se", "server2_se")}
    sig = h.sign_continuity_event(record, participating, msg)
    assert sign.sphincs_verify(record.root_pk, msg, sig)

    # A wrong message must not verify against this signature.
    assert not sign.sphincs_verify(record.root_pk, msg + b"!", sig)


# ---------------------------------------------------------------------------
# RE-CONFIRM 5 — COMPUTER WIPED AT GENESIS
# ---------------------------------------------------------------------------


def test_computer_wiped_at_genesis():
    holders = m.make_holders(FACTORS)
    record, transient = h.genesis(holders, generation=0)
    transient.wipe()
    assert transient.wiped
    del transient  # the computer is gone; it never held a share

    # Account still fully operational: k=3 among the surviving holders.
    msg = b"continuity-event after computer loss (hardened)"
    participating = {n: holders[n] for n in ("usb", "server1_se", "server2_se")}
    sig = h.sign_continuity_event(record, participating, msg)
    assert sign.sphincs_verify(record.root_pk, msg, sig)


# ---------------------------------------------------------------------------
# RE-CONFIRM 6 — RE-ROOT REVOCATION
# ---------------------------------------------------------------------------


def test_reroot_revocation():
    holders = m.make_holders(FACTORS)
    rec0, t0 = h.genesis(holders, generation=0)
    old_seed = bytes(t0.seed)  # copy before wipe
    old_wrapped = dict(rec0.wrapped)
    t0.wipe()

    # Re-root: fresh generation with a brand-new seed and new commitments.
    rec1, t1 = h.genesis(holders, generation=1)
    t1.wipe()

    assert rec1.root_pk != rec0.root_pk
    # Commitments are generation-bound: gen-0 commitments differ from gen-1's.
    assert rec1.commitments != rec0.commitments

    # OLD shares still reconstruct the OLD seed (which is NO LONGER the root).
    old_shares = [
        m.unwrap_share(holders[n], old_wrapped[n])
        for n in ("phone_se", "usb", "yubikey")
    ]
    recovered = shamir.combine(old_shares)
    assert recovered == old_seed
    assert sign.sphincs_keypair_from_seed(recovered).pk != rec1.root_pk

    # And an OLD share presented against the NEW record fails its commitment:
    # generation binding prevents cross-generation share replay.
    old_phone = m.unwrap_share(holders["phone_se"], old_wrapped["phone_se"])
    assert not h.verify_share(rec1, "phone_se", old_phone)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

PROPERTIES = [
    ("1 k TUNING (no 2-way collusion; any 3 pass)", test_k_tuning_collusion_resistant),
    ("2 SHARE AUTHENTICATION (detect + attribute)", test_share_authentication_detects_and_attributes),
    ("3 EXPLICIT ZEROIZATION (buffers zeroed)", test_explicit_zeroization),
    ("4 THRESHOLD + CONTINUITY SIGN", test_threshold_and_continuity_sign),
    ("5 COMPUTER WIPED AT GENESIS", test_computer_wiped_at_genesis),
    ("6 RE-ROOT REVOCATION", test_reroot_revocation),
]


def main() -> int:
    print("=" * 72)
    print("HARDENED PQ ROOT-OF-TRUST CUSTODY  (real SLH-DSA + Shamir + ML-KEM)")
    print(f"  factors = {FACTORS}")
    print(f"  threshold k={K}-of-{N}   (default_threshold({N}) = {h.default_threshold(N)})")
    print("=" * 72)

    holders = m.make_holders(FACTORS)
    t = time.time(); rec, tr = h.genesis(holders); t_gen = time.time() - t
    tr.wipe()
    part = {n: holders[n] for n in ("phone_se", "server1_se", "server2_se")}
    t = time.time(); sig = h.sign_continuity_event(rec, part, b"perf"); t_evt = time.time() - t
    ok = sign.sphincs_verify(rec.root_pk, b"perf", sig)
    print(f"perf: genesis(keygen+split+wrap+commit x{N}) = {t_gen*1000:.0f} ms")
    print(f"perf: authenticated reconstruct + SLH-DSA sign = {t_evt*1000:.0f} ms "
          f"(verify={ok}, sig={len(sig)} B)")
    print("-" * 72)

    failures = 0
    for label, fn in PROPERTIES:
        try:
            fn()
            print(f"PASS  Property {label}")
        except Exception as e:  # noqa: BLE001
            failures += 1
            print(f"FAIL  Property {label}: {type(e).__name__}: {e}")
    print("-" * 72)
    print(f"RESULT: {len(PROPERTIES) - failures}/{len(PROPERTIES)} properties PASS")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
