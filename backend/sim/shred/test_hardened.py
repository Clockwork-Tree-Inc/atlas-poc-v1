"""Property-assertion tests for the HARDENED crypto-shred registry.

Runnable directly:
    PYTHONPATH=. python -m sim.shred.test_hardened     (from backend/)

Prints PASS/FAIL per property and exits 0 iff every property passes.

What this proves on top of `sim.shred.model` / `test_shred`:

  1. BY-CONSTRUCTION: the secret-nonce rule is structural. There is no public
     API to register a commitment without a fresh 256-bit secret opening, so a
     deterministic / linkable commitment cannot be produced even by mistake.
  2. ERASURE: after destroying the opening the row remains (append-only) but is
     unopenable, unlinkable, reveals no System-ID / pseudonym, and NO brute force
     over plausible inputs re-links it — even for an adversary who still holds the
     System-ID secret (the destroyed 256-bit nonce is the whole barrier).
  3. RE-ENROLL FRESH works and is independent of the orphaned row.
  4. ZEROIZATION: the opening's key buffers are provably overwritten with zeros.
  5. METADATA / TIMING (inherent limit, mitigated): batched/rotated insertion
     decorrelates insert timing & order from registration. Row EXISTENCE and
     content already disclosed to a THIRD PARTY are honestly out of scope.
"""

from __future__ import annotations

import inspect
import random
import sys
import traceback

from atlas.crypto.primitives import H, aead_decrypt, random_bytes

from sim.shred.model import System, _commitment
from sim.shred.hardened import (
    HardenedRegistry,
    SecureOpening,
    Receipt,
    RegistrationError,
    Shredded,
    NONCE_BITS,
    public_write_surface,
    _INJECTION_WORDS,
)


# ---------------------------------------------------------------------------
# Test framework (same shape as test_shred.Prop)
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


def _pearson(xs, ys) -> float:
    """Pearson correlation; defined as 0.0 when either series has no variance
    (a constant series carries no information to correlate against)."""
    n = len(xs)
    mx = sum(xs) / n
    my = sum(ys) / n
    cov = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    vx = sum((x - mx) ** 2 for x in xs)
    vy = sum((y - my) ** 2 for y in ys)
    if vx == 0 or vy == 0:
        return 0.0
    return cov / ((vx * vy) ** 0.5)


# ---------------------------------------------------------------------------
# Property 1 — BY-CONSTRUCTION: the secret nonce is structurally mandatory
# ---------------------------------------------------------------------------

def prop1_by_construction() -> Prop:
    p = Prop("PROPERTY 1  BY-CONSTRUCTION (no path to a non-erasable commitment)")
    reg = HardenedRegistry()
    s = System.enroll()

    # (a) register() is the ONLY public method that introduces NEW row data, and
    #     it takes ONLY (system, plaintext); flush() commits already-staged
    #     internal entries and takes NOTHING from the caller. So neither WRITE
    #     path admits a caller-supplied commitment / nonce / opening. (open/links
    #     legitimately consume an ALREADY-ISSUED opening — a read, not a write.)
    surface = public_write_surface()
    p.check("register() exists and takes exactly ['system', 'plaintext']",
            surface.get("register") == ["system", "plaintext"])
    p.check("no public 'append'/'add'/'insert' method exists",
            not any(m in surface for m in ("append", "add", "insert", "put")))
    write_paths = {"register": surface.get("register", []),
                   "flush": surface.get("flush", [])}
    write_injectable = {m: ps for m, ps in write_paths.items()
                        if any(any(w in prm.lower() for w in _INJECTION_WORDS) for prm in ps)}
    p.check("NO write path (register/flush) accepts commitment/nonce/opening material",
            write_injectable == {} and surface.get("flush") == [])

    # (b) the nonce the registry destroys carries >=128 bits of entropy.
    p.check(f"internal nonce carries {NONCE_BITS} bits of entropy (>=128)",
            NONCE_BITS >= 128)

    # (c) a caller literally cannot pass a nonce/commitment/opening keyword.
    rejected = False
    try:
        reg.register(s, b"x", nonce=b"\x00" * 32)   # type: ignore[call-arg]
    except TypeError:
        rejected = True
    p.check("passing a caller-chosen nonce is a TypeError (not accepted)", rejected)

    # (d) determinism is impossible: identical (system, plaintext) inputs yield
    #     DIFFERENT commitments every time, because the nonce is fresh + internal.
    commitments = set()
    for _ in range(64):
        rcpt, _op = reg.register(s, b"identical-input")
        commitments.add(reg.stored_row(rcpt).commitment)
    p.check("64 registrations of identical input -> 64 DISTINCT commitments",
            len(commitments) == 64)

    # (e) a deterministic commitment a naive implementer might build — plain
    #     H(System-ID) with no secret nonce — never appears in the log, and cannot
    #     be produced through the API.
    naive = H(b"atlas/sim/system-id-handle", s._secret)   # a linkable "commitment"
    p.check("naive deterministic H(System-ID) is NOT reachable via the API",
            naive not in commitments)

    # (f) even the opening type refuses a low-entropy nonce, so weakened openings
    #     cannot be smuggled in sideways.
    weak_refused = False
    try:
        SecureOpening(s._secret, b"\x00" * 4)
    except RegistrationError:
        weak_refused = True
    p.check("SecureOpening refuses a short (low-entropy) nonce", weak_refused)
    return p


# ---------------------------------------------------------------------------
# Property 2 — ERASURE: shredded row is unopenable, unlinkable, brute-proof
# ---------------------------------------------------------------------------

def prop2_erasure() -> Prop:
    p = Prop("PROPERTY 2  ERASURE (append-only row survives but is unlinkable)")
    reg = HardenedRegistry()
    s = System.enroll()
    sid_handle = s.system_id_handle()
    pnym = s.pseudonym("forum")
    plaintext = b"attestation sid=" + sid_handle.hex().encode() + b" pnym=" + pnym.hex().encode()

    rcpt, opening = reg.register(s, plaintext)
    row = reg.stored_row(rcpt)
    stored_commitment = row.commitment
    n_before = len(reg)

    # before shred: user can open + link.
    p.check("before shred: row opens to the sealed plaintext",
            reg.open(rcpt, opening) == plaintext)
    p.check("before shred: row links to the System-ID", reg.links(rcpt, opening, s))

    # --- right-to-erasure: destroy the opening ---
    opening.destroy()

    could_open = True
    try:
        reg.open(rcpt, opening)
    except Shredded:
        could_open = False
    p.check("after shred: row can no longer be opened", not could_open)
    p.check("after shred: row no longer links to the System-ID",
            not reg.links(rcpt, opening, s))

    # append-only: the row REMAINS.
    p.check("row REMAINS in the append-only log (not deleted)",
            len(reg) == n_before and reg.stored_row(rcpt) is row)

    # reveals nothing about System-ID / pseudonym.
    p.check("stored row leaks no System-ID handle",
            sid_handle not in row.commitment and sid_handle not in row.sealed)
    p.check("stored row leaks no pseudonym",
            pnym not in row.commitment and pnym not in row.sealed)
    p.check("commitment is a one-way 32B digest", len(row.commitment) == 32)

    # BRUTE FORCE, worst case: the adversary even HOLDS the System-ID secret and
    # tries every *plausible* nonce a naive design might have used. None re-link,
    # because the real nonce is 256 bits of fresh entropy (2^256 search space).
    candidates: list[bytes] = [
        b"\x00" * 32, b"\xff" * 32,
        H(s._secret), H(sid_handle), H(pnym), H(b"nonce"),
        H(s._secret + b"forum"), H(sid_handle + b"/nonce"),
        s._secret, sid_handle, pnym,
    ]
    candidates += [i.to_bytes(32, "big") for i in range(4096)]        # counters
    candidates += [H(str(i).encode()) for i in range(4096)]           # hashed idx
    relinked = any(_commitment(s._secret, c) == stored_commitment for c in candidates)
    p.check(f"no plausible-nonce brute force ({len(candidates)} tries) re-links the row",
            not relinked)

    # public-only adversary with guessed AEAD keys cannot decrypt the sealed blob.
    guesses = [H(b"guess", row.commitment), b"\x00" * 32, H(row.sealed), random_bytes(32)]
    any_opened = False
    for g in guesses:
        try:
            aead_decrypt(g, row.sealed, aad=row.commitment)
            any_opened = True
        except Exception:
            pass
    p.check("no guessed key decrypts the sealed blob", not any_opened)
    return p


# ---------------------------------------------------------------------------
# Property 3 — RE-ENROLL FRESH, independent of the orphaned row
# ---------------------------------------------------------------------------

def prop3_reenroll_fresh() -> Prop:
    p = Prop("PROPERTY 3  RE-ENROLL FRESH (independent of the orphaned row)")
    reg = HardenedRegistry()

    old = System.enroll()
    old_forum = old.pseudonym("forum")
    orphan_rcpt, old_opening = reg.register(old, b"old-attestation")
    orphan_row = reg.stored_row(orphan_rcpt)
    old_opening.destroy()                              # delete the old identity

    # fresh, independent enrolment into the SAME registry.
    fresh = System.enroll()
    fresh_rcpt, fresh_opening = reg.register(fresh, b"fresh-attestation")

    p.check("fresh identity has an independent TSK seed", fresh.tsk_seed != old.tsk_seed)
    p.check("fresh System-ID handle unlinkable to the old one",
            fresh.system_id_handle() != old.system_id_handle())
    p.check("fresh pseudonym differs from the deleted identity's pseudonym",
            fresh.pseudonym("forum") != old_forum)
    p.check("fresh row opens correctly",
            reg.open(fresh_rcpt, fresh_opening) == b"fresh-attestation")
    p.check("fresh row links to the FRESH identity",
            reg.links(fresh_rcpt, fresh_opening, fresh))
    p.check("fresh commitment independent of the orphaned commitment",
            reg.stored_row(fresh_rcpt).commitment != orphan_row.commitment)
    p.check("fresh identity does NOT link to the orphaned (shredded) row",
            not reg.links(orphan_rcpt, old_opening, fresh))
    p.check("orphaned row still REMAINS (append-only), just unlinkable",
            len(reg) == 2)
    return p


# ---------------------------------------------------------------------------
# Property 4 — ZEROIZATION of the opening buffers
# ---------------------------------------------------------------------------

def prop4_zeroization() -> Prop:
    p = Prop("PROPERTY 4  ZEROIZATION (opening buffers overwritten with zeros)")
    reg = HardenedRegistry()
    s = System.enroll()
    _rcpt, opening = reg.register(s, b"attestation")

    sid_buf, nonce_buf = opening.buffers()
    len_sid, len_nonce = len(sid_buf), len(nonce_buf)

    p.check("buffers are mutable bytearrays", isinstance(sid_buf, bytearray)
            and isinstance(nonce_buf, bytearray))
    p.check("before destroy: sid buffer is non-zero", any(sid_buf))
    p.check("before destroy: nonce buffer is non-zero", any(nonce_buf))
    p.check("nonce buffer is 32 bytes (256 bits)", len_nonce == 32)

    opening.destroy()

    # SAME buffer objects, overwritten in place with 0x00, length preserved.
    p.check("after destroy: sid buffer is all zero bytes",
            sid_buf == bytearray(len_sid) and len(sid_buf) == len_sid)
    p.check("after destroy: nonce buffer is all zero bytes",
            nonce_buf == bytearray(len_nonce) and len(nonce_buf) == len_nonce)
    p.check("after destroy: no non-zero byte remains anywhere in the opening",
            not any(sid_buf) and not any(nonce_buf))
    p.check("after destroy: opening reports not alive", not opening.alive)

    raised = False
    try:
        reg.open(_rcpt, opening)
    except Shredded:
        raised = True
    p.check("after destroy: opening the row raises Shredded", raised)
    return p


# ---------------------------------------------------------------------------
# Property 5 — METADATA / TIMING: mitigate via batched write; honest bounds
# ---------------------------------------------------------------------------

class ThirdParty:
    """Someone the user disclosed content to out-of-band. Holds its own copy; the
    registry has no reach into it and never stored it."""
    def __init__(self) -> None:
        self._copy = None

    def receive(self, data: bytes) -> None:
        self._copy = bytes(data)

    def read(self):
        return self._copy


def prop5_metadata_timing() -> Prop:
    p = Prop("PROPERTY 5  METADATA/TIMING (batched write mitigates; honest bounds)")
    N = 128

    # --- IMMEDIATE insertion: insert time & order track registration exactly. ---
    imm = HardenedRegistry(batched=False, clock=_seq_clock())
    imm_rcpts = [imm.register(System.enroll(), b"row")[0] for _ in range(N)]
    imm_req_t = [imm.request_time(r) for r in imm_rcpts]
    imm_ins_t = [imm.insert_time(r) for r in imm_rcpts]
    imm_ins_ord = [imm.insert_order(r) for r in imm_rcpts]
    imm_time_corr = _pearson(imm_req_t, imm_ins_t)
    imm_order_corr = _pearson(list(range(N)), imm_ins_ord)

    # --- BATCHED / rotated write: one shared insert time, shuffled order. ---
    bat = HardenedRegistry(batched=True, clock=_seq_clock(),
                           rng=random.Random(20260716))
    bat_rcpts = [bat.register(System.enroll(), b"row")[0] for _ in range(N)]
    committed = bat.flush()
    bat_req_t = [bat.request_time(r) for r in bat_rcpts]
    bat_ins_t = [bat.insert_time(r) for r in bat_rcpts]
    bat_ins_ord = [bat.insert_order(r) for r in bat_rcpts]
    bat_time_corr = _pearson(bat_req_t, bat_ins_t)
    bat_order_corr = _pearson(list(range(N)), bat_ins_ord)

    p.check("batched write committed all rows exactly once",
            committed == N and len(bat) == N)
    p.check("immediate insert TIME correlates perfectly with registration (~1.0)",
            imm_time_corr > 0.999)
    p.check("batched insert TIMES are all identical (single rotated timestamp)",
            len(set(bat_ins_t)) == 1)
    p.check("batched insert TIME correlation with registration is ~0 (decorrelated)",
            abs(bat_time_corr) < 1e-9)
    p.check("immediate insert ORDER equals registration order (corr ~1.0)",
            imm_order_corr > 0.999)
    p.check("batched insert ORDER is decorrelated from registration (|corr| small)",
            abs(bat_order_corr) < 0.5)
    p.check("batched insert-order correlation << immediate (timing mitigated)",
            abs(bat_order_corr) < abs(imm_order_corr) - 0.4)

    # batching does not harm correctness: a batched row still opens.
    s = System.enroll()
    bat2 = HardenedRegistry(batched=True)
    rcpt, opening = bat2.register(s, b"batched-payload")
    bat2.flush()
    p.check("a batched row still opens correctly after flush",
            bat2.open(rcpt, opening) == b"batched-payload")

    # HONEST BOUND (a): row EXISTENCE cannot be erased — do not pretend to. The
    # append-only log still shows N rows exist after any shred.
    p.check("row EXISTENCE survives on the append-only log (honest, not erased)",
            len(imm) == N)

    # HONEST BOUND (b): content disclosed to a THIRD PARTY is OUT OF SCOPE — it is
    # never stored in the registry, so the registry neither leaks nor can recall it.
    tp = ThirdParty()
    disclosed = b"content the user disclosed out-of-band"
    tp.receive(disclosed)                              # NOT passed to the registry
    stored_blob = b"".join(imm._log.get(i).commitment + imm._log.get(i).sealed
                           for i in range(len(imm)))
    p.check("third-party-disclosed content is not stored in the registry",
            disclosed not in stored_blob)
    p.check("registry exposes no recall path over externally-shared copies",
            not hasattr(imm, "recall"))
    p.check("third party still holds its own copy (registry cannot recall it)",
            tp.read() == disclosed)
    return p


def _seq_clock():
    t = 0

    def now() -> int:
        nonlocal t
        v = t
        t += 1
        return v

    return now


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def main() -> int:
    print("=" * 72)
    print("Atlas hardened crypto-shred — secret nonce enforced BY CONSTRUCTION")
    print("=" * 72)
    props = []
    for fn in (prop1_by_construction, prop2_erasure, prop3_reenroll_fresh,
               prop4_zeroization, prop5_metadata_timing):
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
