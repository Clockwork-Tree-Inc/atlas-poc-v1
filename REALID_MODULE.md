# Atlas Real-ID / Unlinkability / Duress — Assessment Note (Real-ID spec §8.3)

**Showcase build · TEST/DUMMY identity data only.** This module demonstrates the
mechanism with fabricated stand-in IDs. It does **not** ingest any real person's
real government/financial identity — production real-PII handling (KYC,
data-protection, retention law) is a separate, regulated legal/compliance project
explicitly out of scope (§0, §8.3). Goes to the §11 audit before any non-showcase
use.

## What it solves (the problems we flagged)

This module closes the two gaps the threat-coverage pass surfaced and
operationalizes the "accountable attribution" reframe:

| Problem | Closed by | Tests |
|---------|-----------|-------|
| **T-20** cross-epoch linkage (had per-context handles, not per-epoch) | per-epoch pseudonym rotation + DP on side-channels (`pseudonym.py`) | `test_per_epoch_pseudonyms_unlinkable_but_rooted`, `test_dp_bounds_side_channel_counts` |
| **T-7** coerced authentication | behavioural duress channel — canary finger + duress pattern, externally identical, internally withholds (`duress.py`) | `test_duress_externally_indistinguishable_internally_withholds` |
| "Accountable-but-resolvable" pseudonym (the reframe) | verification-status inheritance (L1 private accountability) + `resolve_under_cause` | `test_accountable_resolution_only_under_cause` |

## Partitioning & inheritance model

- **Real-ID child (§1):** one dedicated child holds the (test) ID. The
  partitioning is **structural** — sibling children are derived from independent
  secrets and have no key path to the real-ID material. Asserted:
  `test_partitioning_only_realid_child_can_read` (a sibling's secret cannot
  decrypt the real-ID blob).
- **Verification inheritance (§2, §3):** L0 (live human) / L1 (verified real
  human behind this, ID hidden) / L2 (legal identity surfaced, consented +
  logged). Children present an inherited proof asserting "my root is verified at
  level ≥ L" that reveals neither the ID, the System-ID, nor a sibling link.
- **Non-custody (§4):** on-device (Enclave-protected) and Shamir-split (device +
  user + cloud) modes; the backend holds only the status attestation and at most
  one share. Asserted: `test_non_custody_split_store`.
- **Two modes (§5):** Mode 1 binds a live-human proof to a mock external service
  (Atlas stores no external identity); Mode 2 surfaces the (test) ID on-device on
  consent. Same live-human primitive underneath.

## Tested vs assumed (be explicit)

- **Tested (showcase):** partitioning isolation, inheritance privacy + level
  gating, accountable resolution only-under-cause, non-custody, per-epoch
  unlinkability + DP noise, two modes, duress indistinguishability + withholding,
  one-human-one-root uniqueness. 13 tests pass.
- **Now uses REAL BBS+ (corrected from the earlier stub):** the inheritance
  proof is a genuine BBS+ anonymous credential via a **vetted library**
  (`ursa-bbs-signatures`, Hyperledger Ursa's audited native implementation) — the
  same discipline as liboqs for PQC primitives. One credential → unlimited,
  re-randomized, mutually-unlinkable selective-disclosure proofs (reveal level,
  hide system-id). The hand-rolled nonce/escrow stand-in was **removed**.
  Remaining audit items on this scheme:
  1. **Library maintenance.** Ursa is archived/unmaintained (Hyperledger sunset,
     2022). It is a real, formerly-vetted BBS+; production should track a
     maintained successor (DIF `bbs` / `docknetwork/crypto` / `anoncreds-rs`).
     It is **not** a hand-rolled scheme.
  2. **Classical, not post-quantum.** BBS+ is pairing-based (BLS12-381). A
     post-quantum anonymous credential is an open research area — flagged.
  3. **Holder-disclosure is absolute BY DECISION** (Credential PQC Posture §6).
     Accountability is the holder producing a full-disclosure BBS+ proof under
     cause. A designated-opener / involuntary-opening extension (group signature
     / verifiable encryption) is **rejected, not deferred** — no operator, court,
     or system key can open a proof. Plain BBS+ giving the issuer no opening
     power is exactly the intended property, not a gap.
  2. **DP parameter.** `DPCounter` uses Laplace noise with ε (default 0.5) and
     unit sensitivity. A real deployment needs a privacy-budget accounting model
     across releases (composition), not a per-release ε — flagged for review.
  3. **Duress** is modeled with constant-time hash comparisons and identical
     surface responses; real indistinguishability must also hold at the **timing
     and UI layer on device** (hardware seam) — not provable in the backend sim.
  4. **On-device / Enclave protection** is modeled; the real Secure Enclave
     binding is the iOS path (Swift), verified on hardware.

## Accountability ⇄ unlinkability (how they coexist)

Per-epoch pseudonyms rotate for **observer-unlinkability**, but every pseudonym
still descends from the **same verified System-ID**, and presented verification
tokens are **resolvable to that root only under cause** (`authorized=True`). So
the system is pseudonymous in normal use and **resolvable-to-an-accountable-human
when accountability is legitimately required** — the reframe's exact property.
Uniqueness (one-human-one-root) is preserved at issuance.

## Boundary (restated)

Test/dummy data only. No real PII. No KYC/compliance. External services mocked.
Not for non-showcase use until the cryptographer review + §11 audit sign off.
