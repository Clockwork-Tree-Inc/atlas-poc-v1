"""Property-assertion tests for the hash-based ZK personhood SIMULATION.

Run from backend/ with the sim venv:
    .../simvenv/bin/python sim/zk_personhood/test_personhood.py

Also importable by pytest (test_* functions). Each property prints PASS/FAIL and the
script exits non-zero if any property fails.

The privacy properties (3) are asserted ONLY against `PublicInputs` — i.e. the
information a real STARK verifier is allowed to see — because the plaintext witness in
this model deliberately over-reveals (that is the documented model/ZK gap).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

_HERE = Path(__file__).resolve()
_BACKEND = _HERE.parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from sim.zk_personhood.personhood import (  # noqa: E402
    AuthPathStep,
    MembershipWitness,
    NullifierAlreadyUsed,
    NullifierRegistry,
    VerifiedHumanRegistry,
    commit,
    leaf_hash,
    merkle_root_from_path,
    nullifier,
    prove,
    verify_statement,
)


def _sid() -> bytes:
    return os.urandom(16)


def _blind() -> bytes:
    return os.urandom(16)


def _fresh_registry(n: int, level: int = 3):
    """Build a registry of n verified humans at a given level; return (reg, enrollments)."""
    reg = VerifiedHumanRegistry()
    enrolls = [reg.register(_sid(), level, _blind()) for _ in range(n)]
    return reg, enrolls


# ---------------------------------------------------------------------------
# Property 1 — UNFORGEABILITY
# ---------------------------------------------------------------------------
def test_unforgeability() -> bool:
    """You cannot produce a valid membership witness for a System-ID never registered."""
    reg, enrolls = _fresh_registry(8)
    root = reg.root

    # Sanity: a genuine member verifies.
    honest_w = reg.witness_for(enrolls[0])
    honest = prove(witness=honest_w, root=root, context=b"ctx", required_level=1)
    assert verify_statement(honest), "genuine member must verify"

    outsider = _sid()  # never registered
    outsider_blind = _blind()
    outsider_leaf = leaf_hash(commit(outsider, 3, outsider_blind))

    # Attack A: outsider's real leaf + a genuine member's stolen path -> root mismatch.
    stolen_path = reg.witness_for(enrolls[0]).path
    forged_a = prove(
        witness=MembershipWitness(
            system_id=outsider, level=3, blind=outsider_blind,
            leaf=outsider_leaf, index=0, path=stolen_path,
        ),
        root=root, context=b"ctx", required_level=1,
    )
    assert not verify_statement(forged_a), "forged leaf + stolen path must be rejected"

    # Attack B: keep a genuine member's leaf+path but swap in the outsider's System_ID.
    #   -> opening-consistency check (leaf != H(commit(outsider,...))) fails.
    victim_w = reg.witness_for(enrolls[1])
    forged_b = prove(
        witness=MembershipWitness(
            system_id=outsider, level=victim_w.level, blind=victim_w.blind,
            leaf=victim_w.leaf, index=victim_w.index, path=victim_w.path,
        ),
        root=root, context=b"ctx", required_level=1,
    )
    assert not verify_statement(forged_b), "swapping System_ID under a real leaf must be rejected"

    # Attack C: fabricate an entirely fake path of the right length -> root mismatch.
    fake_path = [AuthPathStep(sibling=os.urandom(32), sibling_is_right=bool(i % 2))
                 for i in range(len(honest_w.path))]
    forged_c = prove(
        witness=MembershipWitness(
            system_id=outsider, level=3, blind=outsider_blind,
            leaf=outsider_leaf, index=0, path=fake_path,
        ),
        root=root, context=b"ctx", required_level=1,
    )
    assert not verify_statement(forged_c), "fabricated path must be rejected"
    # And the fabricated path provably does not reach the real root.
    assert merkle_root_from_path(outsider_leaf, fake_path) != root
    return True


# ---------------------------------------------------------------------------
# Property 2 — UNIQUENESS PER CONTEXT (double-use detectable)
# ---------------------------------------------------------------------------
def test_uniqueness_per_context() -> bool:
    """nullifier is deterministic -> one System_ID = one nullifier per context; the
    NullifierRegistry rejects the second use."""
    reg, enrolls = _fresh_registry(4)
    root = reg.root
    w = reg.witness_for(enrolls[2])
    ctx = b"poll-2026:proposal-42"

    # Determinism: same (System_ID, context) -> identical nullifier every time.
    n1 = nullifier(w.system_id, ctx)
    n2 = nullifier(w.system_id, ctx)
    assert n1 == n2, "nullifier must be deterministic in (System_ID, context)"

    nullreg = NullifierRegistry()

    p_first = prove(witness=w, root=root, context=ctx, required_level=1)
    assert nullreg.accept(p_first), "first use must be accepted"
    assert nullreg.is_spent(p_first.public.nullifier)

    # Second vote in the SAME context, even with a fresh proof object, reuses the
    # same nullifier and must be rejected.
    p_second = prove(witness=w, root=root, context=ctx, required_level=1)
    assert p_second.public.nullifier == n1, "same human+context must yield same nullifier"
    rejected = False
    try:
        nullreg.accept(p_second)
    except NullifierAlreadyUsed:
        rejected = True
    assert rejected, "double-use in the same context MUST be rejected"
    return True


# ---------------------------------------------------------------------------
# Property 3 — CROSS-CONTEXT UNLINKABILITY
# ---------------------------------------------------------------------------
def test_cross_context_unlinkability() -> bool:
    """Same System_ID in two contexts -> two nullifiers with no efficient link, and the
    PUBLIC proof data leaks neither the System_ID nor the other context's nullifier."""
    reg, enrolls = _fresh_registry(4)
    root = reg.root
    w = reg.witness_for(enrolls[0])

    ctx_a = b"app-A:health"
    ctx_b = b"app-B:finance"

    pa = prove(witness=w, root=root, context=ctx_a, required_level=1)
    pb = prove(witness=w, root=root, context=ctx_b, required_level=1)

    na, nb = pa.public.nullifier, pb.public.nullifier

    # Distinct pseudonyms across contexts.
    assert na != nb, "same human in two contexts must produce distinct nullifiers"

    # Model of 'no efficient link': each nullifier is an independent H output, so
    # neither the System_ID nor the sibling nullifier can be read off the public data.
    pub_a = na + pa.public.root + pa.public.context
    pub_b = nb + pb.public.root + pb.public.context
    assert w.system_id not in pub_a and w.system_id not in pub_b, \
        "System_ID must not appear in public proof data"
    assert nb not in pub_a and na not in pub_b, \
        "one context's nullifier must not be derivable from the other's public data"

    # The only shared public value is the (public) tree root — expected, and it does
    # not link the two, since every member shares that same root.
    other = reg.witness_for(enrolls[1])
    po = prove(witness=other, root=root, context=ctx_a, required_level=1)
    assert po.public.root == pa.public.root, "root is common to all members (non-linking)"
    assert po.public.nullifier != na, "different member -> different nullifier in same ctx"
    return True


# ---------------------------------------------------------------------------
# Property 4 — DISTINCTNESS (no collisions across a population)
# ---------------------------------------------------------------------------
def test_distinctness() -> bool:
    """Different System_IDs -> different nullifiers (no collision in the test population)."""
    ctx = b"shared-context"
    ids = [_sid() for _ in range(2000)]
    nulls = {nullifier(sid, ctx) for sid in ids}
    assert len(nulls) == len(ids), "distinct System_IDs must give distinct nullifiers"

    # Also distinct across contexts for the same population (cross-product sanity).
    ctx2 = b"other-context"
    all_nulls = {nullifier(sid, ctx) for sid in ids} | {nullifier(sid, ctx2) for sid in ids}
    assert len(all_nulls) == 2 * len(ids), "no cross-context collisions expected"
    return True


# ---------------------------------------------------------------------------
# Property 5 — LEVEL BINDING (prove level >= required)
# ---------------------------------------------------------------------------
def test_level_binding() -> bool:
    """The commitment binds assurance level L; the proof asserts level >= required."""
    reg = VerifiedHumanRegistry()
    low = reg.register(_sid(), level=1, blind=_blind())   # weak assurance
    high = reg.register(_sid(), level=4, blind=_blind())  # strong assurance
    root = reg.root

    w_low = reg.witness_for(low)
    w_high = reg.witness_for(high)

    # High-assurance human clears a high bar.
    assert verify_statement(prove(witness=w_high, root=root, context=b"c", required_level=4))
    # Low-assurance human clears a low bar...
    assert verify_statement(prove(witness=w_low, root=root, context=b"c", required_level=1))
    # ...but is rejected when a higher level is required.
    assert not verify_statement(prove(witness=w_low, root=root, context=b"c", required_level=3)), \
        "level < required must be rejected"

    # Level is BOUND into the commitment: you cannot relabel a level-1 leaf as level-4.
    #   Presenting the real leaf but claiming level=4 breaks opening consistency.
    forged = prove(
        witness=MembershipWitness(
            system_id=w_low.system_id, level=4, blind=w_low.blind,
            leaf=w_low.leaf, index=w_low.index, path=w_low.path,
        ),
        root=root, context=b"c", required_level=4,
    )
    assert not verify_statement(forged), "level is bound in the commitment; relabelling must fail"
    return True


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
_PROPERTIES = [
    ("1. UNFORGEABILITY (no witness for unregistered System-ID)", test_unforgeability),
    ("2. UNIQUENESS PER CONTEXT (double-use rejected)", test_uniqueness_per_context),
    ("3. CROSS-CONTEXT UNLINKABILITY (independent nullifiers)", test_cross_context_unlinkability),
    ("4. DISTINCTNESS (no nullifier collisions)", test_distinctness),
    ("5. LEVEL BINDING (level >= required, bound in commitment)", test_level_binding),
]


def main() -> int:
    print("=" * 70)
    print("HASH-BASED ZK PERSONHOOD — PROPERTY SIMULATION (reference model)")
    print("=" * 70)
    failures = 0
    for name, fn in _PROPERTIES:
        try:
            fn()
            print(f"[PASS] {name}")
        except AssertionError as e:
            failures += 1
            print(f"[FAIL] {name}\n         assertion: {e}")
        except Exception as e:  # noqa: BLE001
            failures += 1
            print(f"[FAIL] {name}\n         error: {type(e).__name__}: {e}")
    print("-" * 70)
    total = len(_PROPERTIES)
    print(f"RESULT: {total - failures}/{total} properties PASS")
    print("=" * 70)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
