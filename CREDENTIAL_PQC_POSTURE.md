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
  (ML-KEM), signatures (ML-DSA), encryption (AES-256) are post-quantum. The ONLY
  classical primitive is BBS anonymity — shielded behind the PQC tunnel, isolated
  for swap, bounded to a blind re-rootable ID if broken.
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

## 6. Boundaries (§7.3)

A production PQ anonymous-credential scheme (future); real members-of-public PII
(regulated, separate project); Ursa maintenance (showcase uses Ursa; production
tracks DIF). The BBS scheme and the PQ-swap seam are the central
cryptographer-review items.
