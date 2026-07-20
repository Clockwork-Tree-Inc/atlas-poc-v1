"""Property-assertion tests for UNLINK (re-root) + DELETE (crypto-shred).

Runnable directly:  python -m sim.shred.test_shred   (from backend/, '.' on path)
Prints PASS/FAIL per property and exits non-zero if any property fails.
"""

from __future__ import annotations

import sys
import traceback

from atlas.crypto.primitives import H, aead_decrypt, random_bytes

from sim.shred.model import (
    System,
    Registry,
    Opening,
    OperatorForbidden,
    Shredded,
    enroll_in_registry,
    open_row,
    links_with_opening,
    _system_id_secret,
)


# ---------------------------------------------------------------------------
# Adversary / holder link oracles
# ---------------------------------------------------------------------------

def adversary_link(a: bytes, b: bytes) -> bool:
    """A PUBLIC-ONLY adversary that sees two pseudonym handles and no secret.
    Tries every cheap linking strategy available without the System-ID secret.
    Returns True iff it finds a link. For unlinkable handles this must be False.
    """
    if a == b:
        return True
    # shared prefix / suffix would betray a common derivation stem
    for k in (4, 8, 16):
        if a[:k] == b[:k] or a[-k:] == b[-k:]:
            return True
    # naive public "re-derivation" attempts (hash chaining / xor folding)
    if H(a) == b or H(b) == a:
        return True
    if H(b"gen", a) == b or H(b"gen", b) == a:
        return True
    if bytes(x ^ y for x, y in zip(a, b)) in (a, b):
        return True
    return False


def holder_link(tsk_seed: bytes, handle: bytes, generation: int, context: str) -> bool:
    """The SECRET-holder oracle: recompute the pseudonym from the durable root
    and confirm it matches `handle`. This is the (only) efficient link, and it
    needs the tsk_seed the adversary does not have."""
    s = System(tsk_seed=tsk_seed, generation=generation)
    return s.pseudonym(context) == handle


# ---------------------------------------------------------------------------
# Test framework
# ---------------------------------------------------------------------------

class Prop:
    def __init__(self, name: str):
        self.name = name
        self.checks: list[tuple[str, bool]] = []

    def check(self, desc: str, cond: bool) -> None:
        self.checks.append((desc, bool(cond)))

    @property
    def passed(self) -> bool:
        return all(c for _, c in self.checks)

    def report(self) -> None:
        status = "PASS" if self.passed else "FAIL"
        print(f"[{status}] {self.name}")
        for desc, ok in self.checks:
            print(f"        {'ok ' if ok else 'XX '} {desc}")


# ---------------------------------------------------------------------------
# Property 1 — UNLINK (re-root / forward-heal)
# ---------------------------------------------------------------------------

def prop1_unlink() -> Prop:
    p = Prop("PROPERTY 1  UNLINK (re-root / forward-heal)")
    s0 = System.enroll()
    p0 = s0.pseudonym("forum")

    s1 = s0.reroot(user_authorized=True)          # forward-heal to gen 1
    p1 = s1.pseudonym("forum")

    p.check("new-generation pseudonym differs from old (rotated)", p0 != p1)
    p.check("System-ID handle rotated across generations",
            s0.system_id_handle() != s1.system_id_handle())
    p.check("no PUBLIC link between old & new pseudonyms (adversary fails)",
            not adversary_link(p0, p1))
    p.check("WITH the secret the holder CAN link both to one root",
            holder_link(s0.tsk_seed, p0, 0, "forum")
            and holder_link(s0.tsk_seed, p1, 1, "forum"))

    # Forward-heal only (honest bound): old pseudonyms still resolve to OLD gen.
    s0_again = System(tsk_seed=s0.tsk_seed, generation=0)
    p.check("old pseudonyms still resolve to the old generation (forward-heal)",
            s0_again.pseudonym("forum") == p0)
    p.check("re-root does NOT retroactively change old-gen pseudonyms",
            s0_again.pseudonym("forum") != p1)

    # Durable root: re-root keeps the TSK seed (only the System-ID rotates).
    p.check("durable TSK seed unchanged across re-root", s0.tsk_seed == s1.tsk_seed)

    # Holder-authority only — no operator path.
    forbidden = False
    try:
        s0.reroot(user_authorized=False)
    except OperatorForbidden:
        forbidden = True
    p.check("re-root refused without holder authority (no operator path)", forbidden)
    return p


# ---------------------------------------------------------------------------
# Property 2 — CROSS-CONTEXT UNLINKABILITY (before & after re-root)
# ---------------------------------------------------------------------------

def prop2_cross_context() -> Prop:
    p = Prop("PROPERTY 2  CROSS-CONTEXT UNLINKABILITY (siblings, before & after)")
    s0 = System.enroll()
    for gen, sys in (("gen0", s0), ("gen1", s0.reroot(user_authorized=True))):
        forum = sys.pseudonym("forum")
        bank = sys.pseudonym("bank")
        health = sys.pseudonym("health")
        p.check(f"[{gen}] sibling pseudonyms are distinct",
                len({forum, bank, health}) == 3)
        p.check(f"[{gen}] forum/bank not publicly linkable", not adversary_link(forum, bank))
        p.check(f"[{gen}] bank/health not publicly linkable", not adversary_link(bank, health))
        p.check(f"[{gen}] forum/health not publicly linkable", not adversary_link(forum, health))
    return p


# ---------------------------------------------------------------------------
# Property 3 — DELETE / CRYPTO-SHRED on an append-only registry
# ---------------------------------------------------------------------------

def prop3_crypto_shred() -> Prop:
    p = Prop("PROPERTY 3  DELETE / CRYPTO-SHRED (append-only erasure)")
    reg = Registry()
    s = System.enroll()
    # A plaintext that DOES reference the System-ID handle + a pseudonym.
    sid_handle = s.system_id_handle()
    pnym = s.pseudonym("forum")
    plaintext = b"attestation for " + sid_handle.hex().encode() + b" pnym=" + pnym.hex().encode()

    row_id, opening = enroll_in_registry(s, reg, plaintext)
    row = reg.get(row_id)
    n_before = len(reg)

    # Before shred: the user can open + link the row.
    p.check("before shred: row opens to the sealed plaintext",
            open_row(reg, row_id, opening) == plaintext)
    p.check("before shred: row links to the System-ID (full-secret resolver)",
            links_with_opening(reg, row_id, opening, s))

    # --- user exercises right-to-erasure: destroy the opening ---
    opening.destroy()

    # (3a) can no longer be opened or linked
    could_open = True
    try:
        open_row(reg, row_id, opening)
    except Shredded:
        could_open = False
    p.check("after shred (3a): row can no longer be opened", not could_open)
    p.check("after shred (3a): row no longer links to the System-ID",
            not links_with_opening(reg, row_id, opening, s))

    # even an attacker who grabs the raw sealed bytes cannot decrypt it: no
    # guessable key works (the only key is derived from the destroyed opening).
    guesses = [H(b"guess", row.commitment), b"\x00" * 32, H(row.sealed), random_bytes(32)]
    any_opened = False
    for g in guesses:
        try:
            aead_decrypt(g, row.sealed, aad=row.commitment)
            any_opened = True
        except Exception:
            pass
    p.check("after shred (3a): no guessed key opens the sealed blob", not any_opened)

    # (3b) reveals nothing about the System-ID / pseudonyms
    p.check("after shred (3b): System-ID handle not present in the stored row",
            sid_handle not in row.commitment and sid_handle not in row.sealed)
    p.check("after shred (3b): pseudonym not present in the stored row",
            pnym not in row.commitment and pnym not in row.sealed)
    p.check("after shred (3b): commitment is a one-way hash (32B digest)",
            len(row.commitment) == 32)

    # append-only: the ROW REMAINS, yet is effectively erased.
    p.check("row REMAINS in the append-only registry (not deleted)",
            len(reg) == n_before and reg.get(row_id) is row)
    p.check("erasure achieved WITHOUT removing the row (crypto-shred)",
            row.commitment and row.sealed and not opening.alive)
    return p


# ---------------------------------------------------------------------------
# Property 4 — RE-ENROLL FRESH after delete
# ---------------------------------------------------------------------------

def prop4_reenroll_fresh() -> Prop:
    p = Prop("PROPERTY 4  RE-ENROLL FRESH after delete")
    reg = Registry()
    old = System.enroll()
    old_forum = old.pseudonym("forum")
    _, old_opening = enroll_in_registry(old, reg, b"old-attestation")
    orphan_row = reg.get(0)
    old_opening.destroy()                         # delete the old identity

    # Fresh enrolment: a brand-new independent random TSK.
    fresh = System.enroll()
    fresh_forum = fresh.pseudonym("forum")

    p.check("fresh identity has an independent TSK seed", fresh.tsk_seed != old.tsk_seed)
    p.check("fresh System-ID handle unlinkable to the old one",
            fresh.system_id_handle() != old.system_id_handle())
    p.check("fresh pseudonym unlinkable to the deleted identity's pseudonym",
            fresh_forum != old_forum and not adversary_link(fresh_forum, old_forum))
    p.check("fresh identity does NOT link to the orphaned commitment",
            not links_with_opening(reg, orphan_row.row_id, old_opening, fresh))

    # New enrolment produces an independent commitment.
    fresh_row_id, fresh_opening = enroll_in_registry(fresh, reg, b"fresh-attestation")
    p.check("fresh registry row opens correctly",
            open_row(reg, fresh_row_id, fresh_opening) == b"fresh-attestation")
    p.check("fresh commitment independent of the orphaned one",
            reg.get(fresh_row_id).commitment != orphan_row.commitment)
    return p


# ---------------------------------------------------------------------------
# Property 5 — HONEST BOUND: no recall of already-shared content
# ---------------------------------------------------------------------------

class ThirdParty:
    """Someone the user already disclosed content to, out-of-band. Holds its own
    independent copy. The registry / shred machinery has no reach into it."""
    def __init__(self) -> None:
        self._copy: bytes | None = None

    def receive(self, data: bytes) -> None:
        self._copy = bytes(data)

    def read(self) -> bytes | None:
        return self._copy


def prop5_honest_bound() -> Prop:
    p = Prop("PROPERTY 5  HONEST BOUND (already-shared content is NOT recalled)")
    reg = Registry()
    s = System.enroll()
    shared = b"content the user disclosed to a counterparty"

    # user shares out-of-band BEFORE deleting
    tp = ThirdParty()
    tp.receive(shared)
    _, opening = enroll_in_registry(s, reg, shared)

    # user exercises delete/crypto-shred
    opening.destroy()

    # the registry row is erased, but the third party's copy is untouched: the
    # sim makes NO claim to recall it (there is no such API), which is the
    # honest, correct behaviour.
    p.check("crypto-shred erased the registry opening", not opening.alive)
    p.check("third party STILL holds the previously-shared content", tp.read() == shared)
    p.check("sim exposes no recall path over externally-shared copies",
            not hasattr(reg, "recall") and not hasattr(opening, "recall"))
    return p


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def main() -> int:
    print("=" * 72)
    print("Atlas user-rights simulation — UNLINK (re-root) + DELETE (crypto-shred)")
    print("=" * 72)
    props = []
    for fn in (prop1_unlink, prop2_cross_context, prop3_crypto_shred,
               prop4_reenroll_fresh, prop5_honest_bound):
        try:
            props.append(fn())
        except Exception:
            pr = Prop(fn.__name__ + " (raised)")
            pr.check("test executed without exception", False)
            print(f"[FAIL] {fn.__name__} raised:")
            traceback.print_exc()
            props.append(pr)

    print("-" * 72)
    for pr in props:
        pr.report()
    print("-" * 72)
    n_pass = sum(1 for pr in props if pr.passed)
    print(f"SUMMARY: {n_pass}/{len(props)} properties PASS")
    print("=" * 72)
    return 0 if n_pass == len(props) else 1


if __name__ == "__main__":
    sys.exit(main())
