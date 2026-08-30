# Atlas Credential Anonymity & PQC Posture — Assessment Note

The credential-anonymity + post-quantum posture for the BBS layer. The stack is
post-quantum at every network-facing layer; BBS (classical, pairing-based) is the
one non-PQ primitive and is **shielded behind the PQC tunnel, isolated for
crypto-agility, and backstopped by re-rooting**. Security-critical; goes to the
cryptographer + §11 audit. Test/dummy data only.

## 1. The five-layer model (all hold simultaneously)

| Layer | Mechanism | Where | Protects against |
|-------|-----------|-------|------------------|
| 1. Transport | PQC tunnel — ML-KEM-768 + X25519 hybrid (credential channel AND core recognition tunnel) | `realid/pqc_tunnel.py`, `session/recognition.py` | anyone but the authorized verifier seeing the proof — post-quantum |
| 2. Presentation | BBS+ selective-disclosure (vetted lib) | `realid/verification.py` | authorized verifier / collusion LINKING presentations |
| 3. At rest | encrypt pseudonyms + System-ID, non-custodial | `realid/storage.py` | storage breach |
| 4. Blind root | System-ID is blind | `keys/identity.py` | even a BBS break yields only a non-identifying blind ID |
| 5. Recovery | re-rooting from the durable TSK | `realid/rerooting.py` | rotating a compromised System-ID / TSK forward |

**Load-bearing consequence (tested):** every BBS presentation travels INSIDE the
ML-KEM+X25519 tunnel, so the classical BBS layer is exposed ONLY to authorized
verifiers — never to a passive observer or a harvest-now-decrypt-later collector,
who must break ML-KEM (post-quantum) FIRST even to reach the BBS proof.
`test_bbs_presentation_shielded_by_pqc_tunnel` asserts a passive observer sees
only PQC ciphertext (the BBS proof bytes are absent) and cannot open it without
the verifier's KEM secret.

## 2. Protected vs. bounded properties (§6 — stated exactly)

- **Real-world identity — strongly protected.** Not in the credential, not in the
  System-ID; held on the separate non-custodial real-ID child, surfaced only by
  holder-disclosure. **No credential-layer break reaches it.** (`test_partitioning…`)
- **Inter-pseudonym link — protected while crypto holds; bounded + forward-healable
  if broken.** Unlinkable while BBS + the PQC tunnel hold. A break (post-tunnel, by
  an authorized verifier) could correlate PAST pseudonyms under a *blind* System-ID
  — never to the real person — and re-rooting protects the link going forward.
  We do **not** claim the inter-pseudonym link is "fully protected even if BBS
  breaks." (`test_reroot_forward_heals…`)
- **Holder-disclosure — absolute.** Only the user can reveal their identity or
  re-root. No operator, court, or system key can open a proof or re-root a user. A
  designated-opener extension is **rejected, not deferred**. (`test_holder_authority…`,
  `test_accountable_resolution_only_under_cause`)
- **Network-facing PQ posture — full.** Transport is post-quantum on BOTH the
  credential channel AND the **core recognition tunnel** (now the hybrid
  ML-KEM-768 + X25519 handshake, `session/recognition.py`); key exchange
  (ML-KEM), signatures (ML-DSA), encryption (AES-256) are post-quantum. **Two**
  classical primitives remain, both bounded: (1) the **BBS credential** — shielded
  behind the PQC tunnel, isolated for swap, bounded to a blind re-rootable ID if
  broken; and (2) the **public drand beacon** (BLS threshold signature) — classical
  but not a post-quantum risk, because its integrity is hash-anchored, not
  signature-rooted (see §7).
  (`test_hybrid_tunnel_is_post_quantum_and_mlkem_is_load_bearing`)

## 3. Crypto-agility (§3)

BBS is behind a `CredentialScheme` interface (`realid/credential_scheme.py`):
issue / present / verify / selective-disclose / resolve. The identity tree calls
the interface, never BBS internals. `test_agility_swap_scheme_without_changing_
calling_code` runs the identical tree-level flow over `BBSCredentialScheme` (real
BBS+) and a `MockCredentialScheme` drop-in — proving a standardized **post-quantum
anonymous-credential scheme can be swapped in with no change above the interface**.
Optional `ml_dsa_authenticity_*` adds an ML-DSA signature over the non-anonymous
parts so credential AUTHENTICITY is post-quantum (it does NOT make the anonymity
post-quantum — only the authenticity).

## 4. Re-rooting (§5) and TSK rotation (§5.1)

- `reroot_system_id` derives a fresh System-ID from the **durable TSK** and
  re-issues children. The TSK root_handle is unchanged; only the System-ID and
  pseudonyms rotate, so the new generation is unlinkable from the old. Strictly
  user-authority gated — `OperatorForbidden` if not user-authorized.
- `rotate_tsk` is the deepest ceremony: requires the **complete** full-recovery
  parameter set (in-person + live uncoerced biometric + threshold shares + held
  fuzz) AND user authority; cannot occur otherwise (`test_tsk_rotation_requires_
  full_recovery_params`).
- **Honest bound:** re-rooting heals FORWARD; it does NOT retroactively un-link
  PAST activity already correlated under the old System-ID. That past correlation,
  if any, never reached the real identity (blind root).

## 5. Tested vs. assumed

- **Tested:** tunnel shielding; agility swap seam; re-root forward-heal + durable
  TSK; holder-authority (no operator path); TSK rotation parameter completeness;
  non-custody of pseudonym/System-ID material; optional ML-DSA hybrid authenticity.
  7 tests (`tests/test_credential_pqc.py`), on top of the Real-ID suite.
- **Assumed / bounded (audit domain):**
  1. **BBS library** = Ursa (archived); production tracks a maintained successor
     (DIF `bbs` / `anoncreds-rs`). Not hand-rolled.
  2. **No standardized PQ anonymous credential exists** — the swap seam is built;
     the PQ scheme is future (lattice anon-creds / PQ group signatures).
  3. **DP budget composition** (pseudonym side-channels) — per-release ε only.
  4. **Anonymity: computational vs information-theoretic (OPEN — cryptographer).**
     §2 conservatively treats inter-pseudonym unlinkability as breakable if the
     credential assumption breaks. But the PS reference backend (`ps_credential.py`)
     presents a re-randomized signature `(s1,s2)` that is *uniform and independent of
     the credential/messages* (the `r`,`t` randomizers make the exponent uniform),
     plus a statistically-hiding Schnorr SPK over the hidden attributes — i.e.
     unlinkability that appears **information-theoretic** (survives an unbounded /
     quantum adversary). If confirmed, UNFORGEABILITY — not anonymity — is the sole
     classical exposure, and the PQC-tunnel shielding is defence-in-depth rather than
     load-bearing for anonymity. OPEN QUESTIONS: can we claim unconditional anonymity?
     Does it extend to the BBS+/Ursa path, or is §2's conservative framing intentional
     (System-ID commitment hiding, SPK soundness bound, etc.)? **Do not upgrade the §2
     claim until the cryptographer confirms.**

## 6. Boundaries (§7.3)

A production PQ anonymous-credential scheme (future); real members-of-public PII
(regulated, separate project); Ursa maintenance (showcase uses Ursa; production
tracks DIF). The BBS scheme and the PQ-swap seam are the central
cryptographer-review items.

## 7. The public beacon (drand BLS) — classical, but not a harvest-now target

The drand beacon (§3.2) authenticates its rounds with a **BLS threshold signature
on BLS12-381 — classical, pairing-based, no PQ partner** (`beacon/drand.py`,
`verify_drand_signature`). It is the SECOND non-PQ primitive alongside the BBS
credential (§2). It is, however, **not a post-quantum risk**, for a reason specific
to signatures:

- **Harvest-now-decrypt-later does not apply to signatures.** A recorded BLS
  signature holds no secret to decrypt later; the only quantum threat is *forging*
  one, and a forgery only matters at *verification* time.
- **The BLS check is a present-time authenticity gate.** It runs once, at
  ingestion, to reject a lying relay (a self-consistent triple forged by a malicious
  relay) — now, when no quantum computer exists.
- **Durable integrity is hash-rooted, not signature-rooted.** Every round Atlas
  relies on is hash-anchored at ingestion into the append-only chain
  (`ledger/global_anchor.py`: `entry_hash = H(prev, owner, root, drand_round …)`,
  rounds forced monotonic). "This was anchored at round T" therefore rests on SHA-3
  (PQ-secure); a future BLS forgery cannot rewrite an already-grown chain.

**Load-bearing discipline:** never verify an old provenance record by *re-checking*
the drand BLS against a prover-supplied round — always check it against the anchored
chain. While that holds, the classical BLS is safe indefinitely.

**Optional hardening (not required — the anchoring above already removes the
long-term risk):** bind a SECOND, *signature-free* freshness source alongside drand,
so unpredictability survives even a hypothetical BLS forgery. The criterion is a
source rooted in a **hash / proof-of-work (PQ-secure)**, not a signature — e.g. a
PoW chain's block hash (Bitcoin is the most-witnessed instance; any PoW chain
qualifies), or a hash-based VDF over a public seed. Signature-based beacons (NIST
Randomness Beacon, Ethereum RANDAO/BLS) do **not** qualify — they inherit the same
classical-signature exposure. This is belt-and-suspenders for the freshness property
only.
