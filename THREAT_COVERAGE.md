# Atlas Threat Model v2.0 — PoC Coverage Matrix

Maps every threat (T-01…T-25) and guaranteed property (§8.1) of the threat model
onto what the **Tier-3 PoC actually implements**. The threat model describes the
*full intended architecture* (satellites, governance, UBI, server mesh, ZK/DP,
home node); the PoC is the per-instance protocol slice. This matrix is honest
about which is which.

**Legend**
- ✅ **RUN** — executable test passes here (`backend/tests/test_threat_model.py` unless noted).
- ◐ **PARTIAL** — the mechanism is built and tested for one layer, but the threat
  model's full mitigation spans layers not in the PoC.
- 🔧 **HARDWARE-GATED** — test definable, executes on the kit (see `HARDWARE_TESTING.md`).
- ✕ **NOT IN POC** — full-architecture component, not built (Build Spec §12 out-of-scope).
- ⚠ **GAP** — arguably in Tier-3 scope but **not built**; flagged for decision.

## Threat register

| ID | Threat | Status | Evidence / why |
|----|--------|--------|----------------|
| T-01 | PoLE spoofing via mechanical device farm | ◐ PARTIAL | `test_T01_T23…` — single-device Bayesian gate rejects spoof streams, emits no proof. Network entropy correlation + cross-device consensus NOT built (needs population/pilot). |
| T-02 | Replay of PoLE / proof tokens | ✅ RUN | `test_T02…` — capability-token TTL + epoch-bound attestation (provenance verify rejects wrong-epoch liveness). |
| T-03 | Device Key extraction (HW attack) | ◐ PARTIAL | `test_T03…` — device-local material alone can't forge a session (off-device rooting); DevKey identifier-only, not exported. HW tamper-mesh / no-software-read-path is 🔧. |
| T-04 | QRNG beacon prediction / manipulation | ✅ RUN | `test_T04…` — dual-source (needs beacon epoch_key AND server LK) + committed inter-arrival timing. (Satellite-anchored beacon ✕; drand stand-in in PoC.) |
| T-05 | Satellite constellation compromise | ✕ NOT IN POC | No orbital tier (§12). |
| T-06 | MITM device ↔ server mesh | ◐ PARTIAL | `test_T06…` — proof-token tamper rejected; no session key crosses the wire (recognition is key-agreement). mTLS / cert-pinning transport NOT built. |
| T-07 | Coerced authentication under duress | ✅ RUN | **Two arms.** (a) Behavioural duress channel (`atlas/realid/duress.py`, `test_realid.py::test_duress_…`): canary finger + duress pattern, externally indistinguishable, internally withholds the sensitive action. (b) **Local duress slice** (Code Spec Priority 3, `atlas/session/duress_vault.py`, `test_duress_vault.py`, `demos/demo_duress_local.py`): a **panic passcode opens a surface-identical DECOY** while the real storage key stays sealed under the normal code — the panic-derived key provably **cannot unseal the real key** (`test_panic_code_cannot_derive_real_key`); and **zeroize-on-suspicion** destroys the real key so the real vault is a **permanent brick** with no path back to plaintext (`test_zeroize_makes_real_vault_permanent_brick`), while the decoy stays alive for plausibility. GSR/physiological duress is still absent at Tier 3 by design (no GSR on R10). Production sealing = real Secure Enclave; hardware anti-tamper zeroize + true hidden-volume decoy plausibility are stubbed-and-specified (see module honesty note). |
| T-08 | Atlas Recovery ID Card theft | ✅ RUN | `test_T08…` — card share alone insufficient; impostor biometric + card → refused (stratified recovery). |
| T-09 | Home node forensic record access | ✕ NOT IN POC | No home node. |
| T-10 | Server mesh de-anonymizes users | ✕ NOT IN POC | No server mesh / ZK proofs / DP summaries. |
| T-11 | Supply-chain backdoor in secure element | ◐ PARTIAL | Architectural property is testable: device-local/HEK material is non-load-bearing — extracted key alone is useless without the other threshold shares + live PoLE (same assertion as T-03). The HW backdoor itself is 🔧/vendor. |
| T-12 | Governance capture (Sybil / social) | ✕ NOT IN POC | No governance layer. |
| T-13 | UBI issuance parameter manipulation | ✕ NOT IN POC | No economic layer. |
| T-14 | Firmware backdoor via update | 🔧 HARDWARE-GATED | Maps to the attestation seam (`HARDWARE_TESTING.md` (f)); not built in PoC. |
| T-15 | Score manipulation for reward fraud | ✕ NOT IN POC | No scoring / reward engine. |
| T-16 | Data-market reconstruction by vendor | ✕ NOT IN POC | No data market / compute-to-data. |
| T-17 | Ring removal under duress / theft | ✅ RUN | `test_T17…` — liveness break → suspicious removal + RAM wipe; incoherent reconnect → suspicious. |
| T-18 | Epoch rollover manipulation / replay | ✅ RUN | `test_T18…` — tunnel rekeys on beacon advance; a captured prior-epoch key is inert on this-epoch traffic. (Satellite-signed anchors ✕.) |
| T-19 | Interface device theft + offline brute-force | ✅ RUN | `test_T19…` — session key RAM-only and destroyed; ratchet prev-key wiped; no persisted material. |
| T-20 | Cross-epoch user linkage via proof correlation | ✅ RUN | `test_realid.py::test_per_epoch_pseudonyms_…`, `…dp_bounds…` — per-epoch pseudonym rotation + DP on side-channels built (`atlas/realid/pseudonym.py`); rotating handles still root to one verified System-ID for accountability. DP privacy-budget accounting is an audit item. |
| T-21 | DoS on server mesh / beacon | ✕ NOT IN POC | No mesh; single drand stand-in. |
| T-22 | Legal coercion of operator to disclose | ✕ NOT IN POC | Operator-blindness (ZK/DP) not built; also partly §7 out-of-scope. |
| T-23 | AI-generated synthetic entropy spoofing PoLE | ◐ PARTIAL | Same as T-01: single-device gate rejects; multi-layer fusion / cohort-signature detection NOT built. |
| T-24 | Malicious attestor / NGO collusion | ✕ NOT IN POC | No attestor economy / multi-attestor flow. |
| T-25 | Post-quantum adversary (harvest-now-decrypt-later) | ✅ RUN | `test_T25…` — hybrid PQC KEM (ML-KEM-768 + X25519) + forward secrecy by ephemeral keys. |
| T-25b | Post-quantum forgery of the accountability credential | ✅ RUN (contained) | The tunnels/KEM are PQC-hybrid, but the **BBS+** accountability credential (verification-inheritance) is **classically-secure on unforgeability** (discrete log over BLS12-381) — no mature PQC anonymous-credential has these properties. **Privacy/unlinkability of BBS proofs survives a quantum adversary; the signature's unforgeability does not.** **ORIGINAL FINDING (verified from source):** the "verified-human" verdict rested SOLELY on the BBS proof; the **LK/presence was NOT bound into attribution validity** — so a quantum BBS forger could mint a fully-accountable attribution with **no LK and no presence**. **FIX (implemented — Code Spec Priority 1, `provenance/live_binding.py`):** attribution validity is now bound **non-optionally** to a **witnessable-but-secret** live-provenance binding — a hybrid-PQC witness signature over `(content, epoch, authorship, session_commit)` made with a key **derived from the current per-epoch LK**, whose PUBLIC half the server publishes to an append-only `PublicWitnessRegistry`. A recipient verifies against the public registry **without holding the LK** (recipient verifiability preserved); `verify_provenance` requires `live_provenance_ok`, and `accountable` now `all([...,live_provenance_ok])`. Because the witness key is **hybrid PQC**, a *quantum* BBS forger still cannot forge it without the LK. **Adversarial tests (`test_provenance_live_binding.py`, all pass):** `test_forged_bbs_without_lk_is_rejected`, `test_attribution_requires_live_session`, `test_impersonation_produces_mismatch`, `test_backdated_attribution_rejected`, `test_recipient_can_verify_without_lk`. **HONEST RESIDUAL (not "unforgeable"):** forgery is **contained to the coercion/endpoint floor** — an attacker must be **live and present holding the current LK**. Since the LK is **cohort-shared per epoch**, a *present insider* can still produce a live binding — BUT forging **another person's** identity is a **detectable, self-incriminating mismatch** (the authorship signature hashes to the producer, not the claimed victim; see `test_impersonation_produces_mismatch`). So: remote / harvest-then-forge is stopped; present-insider forgery of *others* is self-incriminating; present-insider forgery of *self* remains (that is the endpoint-coercion floor, out of scope for crypto). **PRECISION (confirmed from source, so the claim is stated exactly as strong as it is):** (1) *Cohort-size dependence* — `_witness_seed(lk, epoch_id)` derives from the **LK alone** (no authorship handle), so the witness keypair is **identical across the whole epoch cohort**; the witness signature therefore proves only "*a* live present cohort member," never *which* one. **Per-author unforgeability rests entirely on the authorship key and is independent of cohort size N.** N affects only the LK *exposure surface* (N endpoints hold it) and the witness anchor's anonymity set — not per-author soundness. As N→1 the binding also uniquely pins presence to one user; as N grows the "someone present" set grows but the per-author guarantee is unchanged. (2) *Self-incrimination is cryptographic, not adjacent* — `handle = H(authorship_public)`, and that handle is bound in **both** the authorship signature's transcript **and** the live-binding `attribution_core`. Claiming another's handle requires their public key to hash to it *and* their private key to sign, so impersonation fails at `handle_ok`/`signature_ok` (and independently breaks `live_provenance_ok`) — enforced by the crypto, double-bound. Swaps in via the `credential_scheme.py` agility seam. |

## Guaranteed properties (§8.1)

| Property | Status | Evidence |
|----------|--------|----------|
| Forward secrecy | ✅ RUN | `test_security_properties.py`, `test_T25`. |
| No single point of failure | ◐ PARTIAL | Threshold recovery ✅; but the PoC verifier is a single node and satellites/mesh aren't built (§12). |
| Coercion resistance | ◐ PARTIAL | Behavioural duress channel built (T-07, `atlas/realid/duress.py`); physiological (GSR) duress absent at Tier 3; forensic logging to home node not in PoC. |
| Operator blindness | ✕ NOT IN POC | No server mesh / ZK / DP. |
| Constitutional integrity | ✕ NOT IN POC | No governance / orbital anchors. |
| UBI non-punitive | ✕ NOT IN POC | No economic layer. |
| Proof-not-data | ◐ PARTIAL | Liveness emits proof objects, not raw biometric; raw stream encrypted under DevKey on the phone. "Raw deleted on-device" is sim-level. |
| Epoch-bound proofs | ✅ RUN | `test_T02`, `test_T18`. |
| Triangle separation | ◐ PARTIAL | Ring/wallet/identity separation modeled; the institution + server vertices aren't built. |

## Summary

- **Run-tested here:** T-02, T-04, T-08, T-17, T-18, T-19, T-25 (full), plus the
  built layer of T-01/T-23, T-03/T-11, T-06 (partial). 10 threat-indexed tests
  pass (`tests/test_threat_model.py`), on top of the 81 existing tests.
- **The two former GAPs are now built + tested** by the Real-ID module
  (`atlas/realid/`, `tests/test_realid.py`): **T-07 behavioural duress** and
  **T-20 per-epoch pseudonyms + DP** — plus the accountable-but-resolvable
  verification-inheritance reframe (L0/L1/L2). Showcase, test-data only; see
  `REALID_MODULE.md`.
- **Hardware-gated:** the HW portions of T-03/T-11/T-14 (tamper mesh, firmware
  attestation) — map to `HARDWARE_TESTING.md`.
- **Not in PoC (full architecture, §12):** T-05, T-09, T-10, T-12, T-13, T-15,
  T-16, T-21, T-22, T-24 — satellites, governance, economy, server mesh, ZK/DP,
  home node, data market. No code exists; these need the broader build, not a
  bench test.

**Honesty line:** a ✅ means the PoC's mechanism resists that threat *in
simulation* at the layer tested — not that the full threat-model mitigation
(which often spans the unbuilt tiers) is in place, and not a substitute for the
§11 external audit.
