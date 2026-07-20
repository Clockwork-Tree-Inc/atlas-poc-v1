# Atlas PoC — Cybersecurity & Privacy Review

Whole-system adversarial review of the backend protocol core (the part that runs
and is tested), plus the iOS/JavaCard source. Method: dependency scan
(`pip-audit`), static analysis (`bandit`), dangerous-pattern sweep, and five
parallel adversarial subsystem reviews — **each finding independently verified by
the maintainer before inclusion** (one agent-reported "Critical" was disproven;
one was confirmed by a working exploit and fixed).

## Second adversarial pass (four parallel attackers, each required a working PoC)

A follow-up pass attacked the post-review code (cadence ratchet, freshness nonce,
replay cache, recovery holder-authority) plus the crypto core, realid/provenance,
and tokens/recovery. Every claim was maintainer-reproduced before fixing; the
crypto core, hybrid KEM/sign, recognition agreement, unlinkability, level-gate,
holder-authority ordering, SecureEnclave, forward secrecy and containment all
**resisted**. Confirmed + **fixed** this pass (regression-tested; 148 passing):

| # | Finding | Sev | Fix |
|---|---------|-----|-----|
| P1 | **Inherited verification-proof transplant** — a stranger's valid L1 proof stapled onto attacker-authored content passed as "a verified human is behind this" (accountable attribution, the load-bearing product, was forgeable). | **High** | `provenance/capture.py`: the BBS+ proof is minted by `sign_capture` with a nonce **bound to (author, content, epoch)**; `verify_provenance` recomputes and requires it → a proof for another author/content is rejected. |
| P2 | **Liveness attestation replayable across captures** — `verify_provenance` ignored the freshness `challenge`. | Med | the attestation `challenge` is bound to (author, content, epoch) at capture and checked at verify; a captured attestation answers the wrong challenge. |
| P3 | **`LivenessAttestation.message_for` non-injective** — `|`-delimited fields, so one genuine signature re-parses to a different `epoch_id`/`challenge` (epoch_id is raw beacon bytes, can contain `0x7c`). | Med | length-prefix every field (matches `hkdf_combine`). |
| P4 | **`ReplayCache` unbounded growth + non-atomic check-set** | Med | expiry-aware eviction (size tracks live tokens) + a lock (no TOCTOU even free-threaded). |
| P5 | **RecoveryChildGate lockout bypass** — per-instance counter reset by re-instantiation; unsalted single-iter passcode hash. | Med | counter persisted in the enrolment record; passcode salted + PBKDF2-stretched + constant-time compared. |
| P6 | **`bootstrap_tunnel_key` silent all-zero default** — omitting the in-person PSK rooted the tunnel in a public constant (voiding the MITM-resistance the prior review relied on). | Med | fail **closed**: omission → fresh per-device random root + `bootstrapped` flag, so un-bootstrapped peers don't converge. |
| P7 | Token `expiry=NaN` / NaN clock fail-open (`now > nan` is False). | Low | reject non-finite expiry/clock. |
| P8 | `shamir.combine` accepted index 0 / out-of-range (silent garbage). | Low | validate indices ∈ 1..255. |

Documented (not silently changed): **cross-node** single-use needs a shared
nonce store (same as the nullifier rail); and tying the attestation **enclave key
to the author** remains the hardware App-Attest anchor (P2 binds freshness in
software, the device-key root stays hardware-gated).

> Scope honesty: this is a self-review of a PoC, **not** the §11 external audit.
> Several findings are inherent to the fact that the **Python backend models
> hardware** (Secure Enclave, App Attest, real biometrics, the JavaCard) that
> only exists on the kit — those are marked **MODEL**. They are real gaps in the
> *model's* guarantees and in some over-stated docstrings, and they tell the
> hardware build exactly what it must enforce.

## Status of this pass

- **Verified-and-FIXED in this review:** the level-gate bypass (Critical), the
  X-Wing ciphertext binding (Medium), the drand randomness↔signature binding
  (part of High), the DP CSPRNG + clamp (Medium), the card nonce-retry window
  (High), the Mock verifier no-op (footgun), and several over-stated docstrings.
  **126 tests pass** (2 new regression tests).
- **Disproven:** the "core tunnel has no MITM protection" claim (the tunnel is
  rooted in the in-person `bootstrap_tunnel_key` PSK — verified an MITM cannot
  derive the genuine A↔B tunnel).
- **Remediated since the pass (backend-fixable High/Medium, in order):**
  (1) **recovery holder-authority** — `HolderAuthorityRequired` gate on every
  path (H3, RESOLVED); (2) **attestation freshness nonce** + **token replay
  cache** (H1-freshness and M2, RESOLVED in software); (3) **honest
  trust-anchor / Mode-2 docstrings** — what the software proves vs what stays
  hardware-gated, without faking the App Attest anchor. **129 tests pass**
  (5 new regression tests across the three items).
- **Still documented with remediation (genuinely hardware/design-gated — NOT
  silently changed):** the attestation **trust anchor** (App Attest / DeviceCheck),
  the Mode-2 **release-requires-Enclave** key operation (the per-view challenge
  can't enter the wrapping key), the Enclave matcher rate-limit, nullifier
  atomicity, and the dependency/maintenance items.

---

## FIXED in this review

| # | Severity | Finding | File | Fix |
|---|----------|---------|------|-----|
| F1 | **Critical** | **Assurance-level gate bypass.** `verify_proof` gated on the unauthenticated `InheritedProof.level` field, not the BBS-revealed `level=` message. A genuine **L0** credential with `.level` forged to L2 cleared an **L2** gate (verified exploit). | `realid/verification.py` | gate on the cryptographically-revealed level (`_revealed_level`); require the claim message be revealed. Regression test added. |
| F2 | Medium | **X-Wing combiner dropped the ML-KEM ciphertext**, losing the transcript-binding it claimed. | `crypto/kem.py` | fold `mlkem_ct` into the HKDF combiner. |
| F3 | Resolved | **drand client trusted the relay** — no integrity check on the returned randomness. | `beacon/drand.py` | enforce `randomness == SHA-256(signature)` **and full BLS threshold-signature verification** against the pinned League-of-Entropy public key (quicknet, unchained-G1), validated by a live-round known-answer test. Regression tests added. |
| F4 | Medium | **DP noise used Mersenne-Twister** (predictable) and could hit `log(0)→-inf`. | `realid/pseudonym.py` | CSPRNG (`secrets`) + clamp `u` off the endpoints. |
| F5 | High (model) | **Card nonce stayed live on failed/replayed arming** (retry window). | `payment/card.py` | consume the nonce up front — any arming attempt retires the challenge. |
| F6 | Med/footgun | **`MockCredentialScheme.verify` was a no-op** (signature unchecked). | `realid/credential_scheme.py` | verify the signature (still not unlinkable — never ship). |
| F7 | doc | Over-stated docstrings: fuzzy "reveals nothing", etc. | `crypto/fuzzy.py` | corrected then RESOLVED by removal — the fuzzy module was RETIRED (TRUST_LAYER #7). |
| F8 | Medium | `cryptography 41.0.7` allowed (multiple CVEs). | `requirements.txt` | pin `>=44.0.1`. |

## OPEN — design / hardware decisions (documented, not silently changed)

### High

- **H1 — Attestation has no trust anchor and no freshness (MODEL).**
  *Update (remediated in part):* the **freshness** half is now closed in
  software — `LivenessAttestation` carries a verifier `challenge` folded into the
  signed message, and Mode-2 `open_message` picks a fresh challenge per view and
  rejects any attestation that doesn't answer it (regression test
  `test_mode2_rejects_replayed_stale_attestation`). The **trust-anchor** half
  (proving the key is a genuine non-extractable Enclave key, not a self-minted
  one) stays hardware-gated — App Attest / DeviceCheck — and is now stated
  honestly in the docstrings rather than overclaimed. Original finding:
  `LivenessAttestation`
  carries its own `enclave_public`; `verify()` checks the signature against that
  same field, so anyone can mint a self-signed `operate=True` attestation, and it
  has no per-view nonce (replayable across messages within an epoch). In Mode-2 a
  *seal-time* `enclave_requirement = H(recipient_enclave_public)` stops swapping in
  a *different* enclave, but the recipient (or anyone with the recipient's enclave
  secret) can still assert `operate=True` with an arbitrary `pole_digest` — the
  PoLE math is never enforced at the gate. *Remediation:* on hardware the enclave
  key is pinned by **App Attest** at enrolment and the attestation must include a
  fresh verifier challenge/nonce; the verifier must check against the *enrolled*
  key, not the carried one. `payment/enclave_arming.py` has the same gap (no
  pinning of the arming attestation's enclave key) — **High** for payment.
- **H2 — Mode-2 "verified-human-only" is a software gate, not a cryptographic
  binding (MODEL).**
  *Update:* freshness/anti-replay is now enforced (the gate demands a signature
  over a per-view challenge) and the docstrings now state honestly that this is a
  software gate plus a hardware-gated key-release. The **core** critique below is
  unchanged and remains hardware-gated: the per-view challenge cannot be folded
  into the wrapping key (the sender seals before any view's challenge exists), so
  a tunnel-key holder can still derive the gate key directly. True
  release-requires-Enclave is a hardware key operation the backend cannot
  enforce. Original finding: the gate key = `HKDF(tunnel_key, beacon_component,
  enclave_requirement)`, and both extra inputs are plaintext in the message. Anyone
  holding the tunnel key can derive the gate key and unwrap **without** a live
  attestation (the `att.operate` check is control-flow, not key material). So
  "stolen device / bot / offline cannot view" holds in the tests only because they
  call `open_message`; a real attacker computes the gate key directly.
  *Remediation:* bind the content key so release **requires** a fresh enclave
  attestation inside the Secure Enclave (the spec's intent) — a hardware key-release
  operation, like the recovery Enclave seal. The backend cannot enforce this.
- **H3 — Recovery paths are gated on caller-asserted booleans, not holder
  authority.** *Update (RESOLVED in the backend model):* every recovery path
  (`recover_via_card` / `recover_in_person` / `recover_total_loss`) and the
  `RecoveryChildGate` now require an explicit `user_authorized` holder-authority
  flag and raise `HolderAuthorityRequired` **before** any attestation/biometric
  work — mirroring `rerooting.py`'s `OperatorForbidden`, so no operator/court/
  system code path can stand in for the holder (regression test
  `test_recovery_requires_holder_authority_no_operator_path`). The real binding
  remains the live biometric + threshold + in-person ceremony the paths already
  require. Original finding: the paths took `attested`,
  `in_person_trusted_context`, `controlled_capture` as plain bools with no
  `OperatorForbidden`-style check; any caller setting them `True` with a
  close-enough biometric + one portable share reconstructed the TSK.
- **H4 — Enclave robust matcher: 35% bit-diff threshold + no rate-limit (MODEL).**
  `ROBUST_MATCH_MAX_BIT_DIFF = 0.35` with unlimited `release()` attempts invites
  sample-grinding toward acceptance. *Remediation:* on hardware Apple's matcher +
  Secure Enclave attempt-limiting replace this model; document the FAR target
  (`HARDWARE_TESTING.md` seam b1) and add lockout if the model is ever used.

### Medium

- **M1 — `SessionKey.destroy()` cannot wipe the `bytes` copies it already handed
  out.** `.key` returns immutable `bytes`; HKDF/ratchet/`tunnel_key`/`_hs` copies
  linger until GC (CPython can't zeroise `bytes`). Containment = "key raises on
  use," not "no copy in RAM." *Remediation:* document the weaker guarantee; on
  hardware the keys live in the enclave.
- **M2 — Capability tokens are replayable within their TTL.** *Update (RESOLVED):*
  added `tokens.ReplayCache.verify_once()` — the first valid presentation consumes
  the token nonce and every later presentation of the same token is rejected even
  while the MAC/TTL still check out; failed presentations never record a nonce (no
  cache poisoning). Stateless `verify()` is kept for the multi-use case. Regression
  tests `test_capability_token_single_use_replay_cache` and the strengthened T-02.
  Original finding: the nonce was in the MAC but never recorded; `verify` had no
  seen-nonce cache, contradicting the T-02 "replay" claim.
- **M3 — Nullifier check-and-set is not atomic** (`payment/nullifier.py`): two
  concurrent submits of the same descriptor both pass `is_spent()` → double-spend.
  *Remediation:* atomic check-and-insert / DB unique constraint on the rail.
- **M4 — Fuzzy extractor leaks biometric structure** (code-offset secure sketch).
  **RESOLVED (2026-07-17): the fuzzy extractor is RETIRED (TRUST_LAYER #7).** Atlas now
  extracts no key from raw biometrics and stores no sketch; biometric matching is the
  Secure Enclave (device-present) or the live recovery person (total loss). The leak is
  eliminated by removal, not mitigated.
- **M5 — Hybrid signatures have no per-context domain separation.** A signature
  over bytes `m` is valid in any context reusing the keys. *Remediation:* sign
  `H(context_label || m)`.
- **M6 — `_revealed`/`_wipe_session` leaves `tunnel_key` and in-flight `_hs`
  after a liveness break.** `destroy()` clears the session key + prev bytes but not
  the evolving tunnel key. *Remediation:* zeroise `tunnel_key` and `_hs` in
  `_wipe_session`.
- **M7 — Bayesian liveness gate accepts unbounded likelihoods.** A crafted stream
  (`P(S|¬L)→0`) drives the posterior past π* in one step. The gate's integrity
  depends on an honest, calibrated likelihood source (the on-device sensor path).
  *Remediation:* clamp likelihood ratios, require a minimum sample count.

### Low / Info / By-design

- AES-GCM random-96-bit nonces with long-lived keys (vault) — safe to ~2³²
  msgs/key; add usage caps / key rotation. **Low.**
- `assert_non_custody` is a weak heuristic (only catches `bytes`/`Share`). **Low.**
- `SplitStore` holds all 3 shares in one object; non-custody is convention-only. **Low.**
- Duress withholding is observable in the *downstream* action (a coercer who
  demands the high-value action sees it fail) — indistinguishable only at the auth
  surface. By design; documented now. **Low.**
- `H()` concatenates without length-prefixing (only `hkdf_combine` frames inputs);
  fine for the fixed-length uses (handles, pseudonyms) but not domain-rigorous. **Low.**
- `pickle` in `demos/demo_milestone5_photo.py` (demo transport on authenticated,
  tunnel-decrypted input). Replace with explicit serialization. **Low.**
- **Ursa BBS is archived/unmaintained** — supply-chain risk (no security patches);
  production tracks a maintained successor (DIF `bbs`/`anoncreds-rs`). Already
  flagged. **Medium (supply-chain).**
- Transitive dep CVEs via `requests` (urllib3/idna) — Mac path only. **Low.**

## Confirmed SOUND

Shamir 2-of-3 (GF(256) + CSPRNG coeffs); HKDF length-prefix framing; the hybrid
signature genuinely requires **both** components; sibling-child isolation
(forward HKDF derivation, one-way); re-rooting durability + unlinkability; the
threshold actually requires 2 factors (no single-factor TSK); stolen-card-alone /
compromised-phone-alone cannot pay; arming↔(descriptor, card) binding;
verify-before-sign ordering; BBS+ presentations are re-randomized/unlinkable and
the system-id stays hidden (holder-disclosure is the only opening path);
the PQC tunnel wrap; the message ratchet's forward secrecy / break-in resistance;
**the core recognition tunnel is rooted in the in-person bootstrap PSK, so a pure
network MITM gets DoS, not compromise** (verified). No secrets are logged or
persisted anywhere in the backend.

## Privacy summary

- **No real PII anywhere** (test/dummy data only, by rule). No secret material is
  logged or written to disk in the backend.
- **Unlinkability:** per-epoch pseudonyms are one-way and unlinkable across epochs;
  BBS+ presentations are unlinkable; the System-ID is blind and re-rootable.
- **Metadata surfaces to watch:** the `SurfaceLog` retains a `{context, level}`
  trail of each L2 real-ID surface (not the ID itself) — minimize/rotate. The core
  recognition tunnel is **direct device-to-device** with **no relay/onion
  metadata protection** (who-talks-to-whom and IP are exposed) — a deliberate
  non-goal vs. e.g. SimpleX, but the honest privacy boundary.
- **DP** now uses a CSPRNG but still lacks **budget composition** across releases
  (a repeated-query observer can average out the noise) — production needs an
  accountant.

## The single most important takeaway

The cryptographic *primitives* and most *constructions* are sound, and one real
exploitable soundness bug (the level-gate bypass) was found and fixed. The
**residual High-severity items are concentrated where the Python backend models
hardware it can't enforce** — the attestation trust-anchor, the Mode-2 liveness
binding, and recovery authority. Those are precisely the properties that become
real on the Secure Enclave + App Attest + JavaCard, and they are the **central
items for the §11 external audit and the hardware bring-up**. Until then, the
backend's "verified-human" and "stolen-device-can't" guarantees should be read as
*modelled, not enforced*.
