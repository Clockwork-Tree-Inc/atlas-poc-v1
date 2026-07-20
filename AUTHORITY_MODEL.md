# Atlas Authority Model — Cross-Boundary Permissioned Grants (Phase D design)

> The authorization subsystem: who may grant access to what, at what scope, across borders.
> ONE mechanism for Space invitation, org→person credentialing (APA→doctor), and org→org
> accreditation (Guild). **This is the sharp edge — privilege-escalation lives here.** Design +
> adversarial pressure-test come *before* implementation (PLATFORM_PLAN §2, §10 Phase D).

**Not inventing crypto.** This is capability-based security / delegatable credentials — the
macaroon (Google) + SPKI/SDSI model — adapted to Atlas: personas as principals, grants as signed
provenance events, the ledger as the audit log, the personhood gate as the sybil defense.

---

## 1. Core object — a Grant (a delegatable capability)

```
Grant {
  grantor:    persona handle        # who is granting (a principal)
  grantee:    persona handle        # who receives (a principal; verified human for accountable rights)
  resource:   bytes                 # what: a Space id, a credential type/scope, an org id
  rights:     RightSet              # the specific rights conferred (a subset lattice — see §3)
  caveats:    [Caveat]              # constraints: expiry, scope narrowing, "one channel", "read-only"
  delegable:  bool | depth          # may the grantee re-delegate? (and how deep)
  parent:     hash | ROOT           # hash of the parent grant in the chain (ROOT = a root authority)
  epoch:      drand_round           # time binding
  sig:        grantor_signature     # over H(all fields above) — unforgeable without grantor's key
}
```

A grant is an **append-only ledger event** (auditable: who admitted whom, at what level, when) — not
a mutable DB flag.

---

## 2. Roots — where authority begins

Every valid grant chain terminates at a **root authority for that resource**:

- **Space** → the root is the Space **owner** (whoever created it / holds the threshold root).
- **Credential** (APA→doctor) → the root is an **accreditation root** that legitimately anoints the
  issuer. APA's authority to credential doctors is itself a grant rooted in the Guild/accreditation
  tier — so `doctor ← APA ← accreditation-root` is one chain.
- A grant is valid **iff** its chain verifies back to a root that legitimately controls the resource.
  (No global super-root; roots are per-resource — a Space owner is root of their Space, not yours.)

---

## 3. The invariants (the security core)

**I1 — Rooted.** Chain terminates at a root that controls the resource. Unrooted → invalid.

**I2 — Monotonic attenuation (the load-bearing invariant).** Along a delegation chain, rights only
**narrow or stay equal**, and caveats only **accumulate**:
```
rights(child) ⊆ rights(parent)      AND      caveats(child) ⊇ caveats(parent)
```
Enforced at VERIFICATION (each link is checked). A delegate can **never** hold more than its delegator;
its delegator never held more than *its* delegator; back to the root. Privilege escalation is
structurally impossible — a grant claiming more than its parent simply fails to verify.

**I3 — Delegation gate.** `delegable` must be true (and depth > 0) for the grantee to grant onward; a
non-delegable grant is a dead end. Re-delegating a non-delegable grant produces a grant whose parent
does not authorize delegation → invalid.

**I4 — Border-crossing = you can only pass what you hold.** To grant on resource R you must *hold* a
delegable grant on R (rooted at R's controller). "An admin can only invite across borders they can
cross" is not a special rule — it *falls out of* I1+I2+I3: no held grant on R → no rooted chain → any
grant you sign is invalid.

**I5 — Chain continuity.** `parent` is bound by hash, and the parent's `grantee` MUST equal this
grant's `grantor` (you can only extend a chain you're the tip of). Prevents splicing a grant onto an
unrelated parent to inherit its authority.

**I6 — Verifiable by anyone.** Walk the chain from the presented grant to the root, checking every
signature, every attenuation step (I2), continuity (I5), validity/expiry, and non-revocation. No
trusted verifier — it's cryptographic and offline-checkable.

**I7 — Revocable (attested).** A signed revocation event (by the grantor or any ancestor) on the
ledger. Verification rejects a grant if it or any ancestor is revoked → revoking a parent kills the
whole subtree. Revocation is monotone and auditable.

**I8 — Personhood gate.** For **accountable** rights (economic, admin, credential-issuing), the
grantee must be a **verified unique human** (real-ID-bound, disclosable under cause). Grants of
accountable rights to unverified/pseudonymous-only personas are refused. (Non-accountable rights —
read a public Commons — need no such binding.)

**I9 — Proof-of-possession at use.** A valid chain is necessary but **not sufficient** for access.
Because grants are public ledger events, using one requires the presenter to **sign a fresh
single-use challenge** with the leaf grantee's key (`verify_access`). `verify_chain` alone validates
structure, never grants access.

**I10 — Forward-secure root (implemented).** The root signer is a **forward-secure ratchet**
(`fs_sign`): the epoch is intrinsic to the key (Merkle leaf position), state advances one-way, past
secrets destroyed — so a compromised current signer cannot forge a *past* epoch (no backdating). The
legacy HybridSig-root path retires a rotated-out root (fail-safe). A **ledger-anchored re-root** for
*actual current-key compromise* (the future, which forward-secrecy does not cover) is the remaining
follow-on. See §Resolution.

**I11 — Understand every caveat or deny.** A verifier rejects any grant carrying a caveat key it does
not recognize (the macaroon rule). An attenuating caveat can never be silently voided by a resource
that doesn't understand it.

---

## 4. Threat model — the adversarial pressure-test (design must defeat each)

| # | Attack | Defeated by |
|---|--------|-------------|
| A1 | **Escalate on delegate** — B grants C more than B holds | I2: child rights ⊄ parent → chain fails to verify |
| A2 | **Upward leak / confused deputy** — trick an admin into granting beyond their scope | I2+I4: any grant is capped by the signer's *own held* rights, regardless of what they're asked |
| A3 | **Forge a grant** | I6: signatures + rooted chain; no grantor key + valid parent = no valid grant |
| A4 | **Re-delegate a non-delegable grant** | I3: parent's `delegable` false → child unauthorized |
| A5 | **Grant on a resource you don't control** | I1+I4: no rooted chain to that resource's controller |
| A6 | **Chain splicing** — attach a grant to a richer unrelated parent | I5: parent hash + grantee==grantor continuity + sigs |
| A7 | **Replay / stale grant** | expiry caveat + epoch binding; verification rejects expired |
| A8 | **Use-after-revoke** | I7: verification checks the revocation ledger; revoked ancestor kills the subtree |
| A9 | **Sybil grantee** — grant accountable rights to fake personas | I8: personhood gate on accountable rights |
| A10 | **Widen via caveat removal** | I2: caveats only accumulate; a grant with fewer caveats than its parent fails |
| A11 | **Ambiguous rights encoding** (grant-for-X reused as grant-for-Y) | length-prefixed, domain-separated grant encoding (same discipline as the ledger/claim framing) |
| A12 | **Root impersonation** — claim to be the resource root | root identity is pinned to the resource (Space threshold root / accreditation root pubkey); a different root doesn't control the resource |
| A13 | **Backdating a root grant** from a compromised root | **✅ Defeated (forward-secure root, implemented + integrated).** `fs_sign` provides a ratcheted signer (Merkle root over per-epoch leaves; state advances one-way, past secrets destroyed). `issue_fs` + `verify_chain(resource_root=FSPublicKey)` bind a root grant's signing leaf to its epoch via Merkle membership — the epoch is *intrinsic to the leaf's tree position*, so a compromised current signer cannot reconstruct a past leaf and cannot backdate. Proven by test (compromise at epoch 3 → an "epoch 0" root grant is rejected), Python + Swift, with Merkle-glue parity. *Reference posture:* per-leaf HybridSig + Merkle models the property; production = XMSS/LMS (SP 800-208). **Compromise recovery (the future):** a **ledger-anchored re-root** (`reroot.py`) — authorized by an INDEPENDENT recovery key (not the compromised signing key) and anchored (unforgeable cutover); after it the old root is retired (its grants no longer verify) and authority continues under the fresh root. Implemented + tested (thief can't re-root; old root retired), Python + Swift. |
| A14 | **Bearer-token replay** — grants are public ledger events, so anyone who reads a chain presents it and gets the rights | `verify_chain` is **not** an access gate; `verify_access` additionally requires the presenter to sign a fresh single-use challenge with the leaf grantee's key (proof-of-possession, I9) |
| A15 | **Revoke-as-DoS** — a griefer drops a victim's grant_id into an unauthenticated revocation set | revocations are **signed** and honored only if the revoker is on the target's authority line (grantor/ancestor); unauthorized/forged revocations are ignored (I7 refined) |
| A16 | **Caveat fails open** — a resource that doesn't recognize a caveat silently voids it | a verifier must understand every caveat or **deny**: `verify_chain` rejects any grant carrying a caveat key not in `understood_caveats` (+ built-in `expiry`) (I11) |

> A13–A16 (and the `now`-required footgun) surfaced in **independent adversarial review** — the chain
> algebra (A1–A12) held; the gaps were all at the boundary (keys, use, revocation). **A14/A15/A16 are
> fail-closed with tests. A13 was re-opened by a second review** (the first "fix" checked an
> attacker-controlled `epoch`) and is now **defeated by a forward-secure ratcheted root signer —
> IMPLEMENTED + integrated, Python + Swift + parity** (§Resolution). Remaining A13 follow-on: a
> ledger-anchored re-root for *actual* current-key compromise.

## Resolution — A13: a forward-secure ratcheted root, not a rotation cert

**Root cause.** Rotation left the old key alive with an epoch that is just a self-asserted signed
field — nothing binds *which key signed* to *when*, so the grantor picks any epoch. That disconnect
**is** the backdating hole. Anchoring the self-asserted epoch treats the symptom.

**Structural fix.** Make the epoch **intrinsic to the key** with a **forward-secure / key-evolving
signature**: one fixed public key, a secret that ratchets one-way per epoch, **past secret destroyed
on advance**. Then an epoch-*t* grant can only be produced by `sk_t`; a compromised *current* key
cannot reconstruct a past secret to backdate → A13 dies by construction (no epoch-field check, no
per-grant ledger lookup). Old grants still verify (fixed pubkey + epoch baked into the signature).
This also matches the architecture — the session key and the server-share proactive ratchet already
evolve forward and destroy the past; the root signer was the one discrete self-signed swap against
that current.

**Honest split (don't over-claim the ratchet either).** Forward-secure protects the **past**, not the
**future**: a stolen `sk_current` can still sign current/future epochs. So:
- **Ratchet** (normal forward evolution) → kills backdating (A13), forward-secret, offline-verifiable.
- **Ledger-anchored re-root** (a discrete jump to a fresh, unrelated key) → for *actual current-key
  compromise*; that event is anchored so an attacker can't backdate around it.

**PQ-native primitive:** **XMSS or LMS** (stateful hash-based, NIST SP 800-208) *are* forward
ratchets — state only advances, a one-time key is never reused or reversed — and fit the hash-based
posture better than ML-DSA+Ed25519 wrapped in a rotation cert. That is what the root signer should be.
**Cadence** is a policy knob (see below); default coarse + drand-aligned.

---

## 5. What it powers (one mechanism, three faces)

- **Space invitation** — owner (root) grants `member`/`guest`/`admin` on the Space, scoped by caveats
  ("one channel", "read-only", "no re-invite"); guests re-invite only if `delegable` and only a subset.
- **Org → person credential** — an accredited org (holding a delegable `issue-credential` grant rooted
  in the Guild tier) issues a credential to a person; the credential *is* a leaf grant; the viewer
  verifies `person ← org ← accreditation-root`.
- **Org → org accreditation (Guild)** — a root anoints an org with a delegable `accredit` right; that
  org can accredit others *within* the subset it holds. Same chain, one level up.

---

## 6. Implementation plan (reference-first, adversarial tests up front)

Python reference (`atlas/authority/`), then Swift + parity:
1. `Grant` + `RightSet` (subset lattice) + `Caveat` types; canonical, length-prefixed, domain-separated
   encoding (A11).
2. `issue(root, ...)`, `delegate(parent_grant, holder_key, subset, added_caveats)`, `revoke(...)`.
3. `verify(grant, resource_root_pubkey, revocation_log, now)` — the single fail-closed checker
   enforcing I1–I8.
4. **Adversarial test suite mirroring §4** — each row A1–A12 is a test that MUST fail-closed. Plus
   happy-path delegation-chain + revocation-subtree tests.
5. Ledger integration (grants + revocations as events).

**Not in Phase D:** the Space *UI*, the credential *formats* (W3C VC interop is Phase E), the economic
rights. D is the authority *engine* + its adversarial proof.

---

## 7. Open questions to settle before coding

1. **RightSet shape** — a fixed lattice (read < post < invite < admin) per resource type, or a free
   capability set? (Lean: per-resource-type lattice + orthogonal capability flags.)
2. **Revocation propagation** — check-time (walk ancestors against a revocation log) vs. short-lived
   grants + re-issue. (Lean: check-time against a ledgered revocation set; short expiries as defense
   in depth.)
3. **Root rotation** — ✅ RESOLVED (A13). Forward-secure ratcheted root (`fs_sign`, backdating rejected)
   + **ledger-anchored re-root** (`reroot.py`, recovery-authorized compromise recovery) — both
   implemented + integrated, Python + Swift. Past (ratchet) and future (re-root) are both covered.
4. **Offline verification vs. revocation freshness** — revocation is now **authenticated** (I7/A15).
   RESIDUAL follow-on: tier the *freshness* requirement by stakes — accountable rights should require a
   fresh revocation view (a drand-epoch bound or an online check), which `verify_chain` accepts inputs
   for but does not yet enforce by tier.
