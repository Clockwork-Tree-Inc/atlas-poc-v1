# What the tests actually assert (and what they don't)

"53 green" means the code does what the tests check — not that the tests check
the right things. For a security substrate the gap between those two is where the
risk lives. This document sorts the suite into **security property** (an attacker
tries X; we assert X fails), **functional** (normal input → expected output), and
**gaps / assumptions** (not covered, or assumed rather than verified).

It also records one fake-pass that existed in the first cut and how it was fixed.

## The fake-pass that was here, and the fix (§22.1)

The original `test_qrng_committed_interarrival_timing` asserted
`d1.randomness != d2.randomness` across two fires. That passed **trivially**
because a fresh random entropy core is drawn on every fire — so it would have
stayed green even if the inter-arrival timing were never bound into the key
material (the "decorative forward secrecy" §22.1 warns about). It proved nothing
about the commitment.

Fix: `ServerQRNG.fire(..., entropy_core=)` now lets a test hold the core
**constant** so timing is the only variable.
`test_timing_is_committed_into_key_material_not_just_observed`
(in `tests/test_security_properties.py`) asserts that with the same core, two
different arrival patterns produce **different** key material, and that the same
core + same timing reproduces it. That actually proves the timing is committed.

## Security-property tests (adversarial)

XIV.5 §21 tier-1 properties — `tests/test_security_properties.py`:

| Property | Test | Attacker capability modelled |
|----------|------|------------------------------|
| Timing committed, not observed (§22.1) | `test_timing_is_committed_into_key_material_not_just_observed` | controls entropy core; varies only timing |
| Forward secrecy (prior epoch) | `test_forward_secrecy_later_key_cannot_read_earlier_epoch_ciphertext` | full capture of epoch e+1 key |
| Replay / epoch-binding | `test_replayed_recognition_is_rejected_after_beacon_advance` | replays last epoch's tunnel key |
| Replay window boundary (§4) | `test_recognition_is_constant_within_epoch_but_changes_with_beacon` | replays within vs across epoch |
| Off-device rooting | `test_off_device_rooting_session_key_requires_beacon_and_lk` | holds device-local material, not beacon/LK |
| Off-device rooting | `test_off_device_rooting_tunnel_diverges_without_shared_beacon` | cannot supply the live beacon |
| Recognition needs both keys | `test_recognition_requires_both_keys_one_alone_insufficient` | holds one session key + both public contributions |
| Containment | `test_containment_session_inert_after_liveness_break` | seizes device right after a liveness break |

Other genuine security-property assertions elsewhere in the suite:

- `test_session.py::test_outsider_cannot_compute_recognition` — eavesdropper with only public contributions gets a different tunnel.
- `test_session.py::test_recognition_rekeys_when_beacon_advances` — re-key on beacon advance.
- `test_session.py::test_mode2_verified_human_only_gate` — Mode 2 denies offline / not-live / expired-epoch.
- `test_session.py::test_stolen_device_cannot_open_mode2_after_wipe` — containment + Mode-2 gate together.
- `test_session.py::test_message_ratchet_forward_secrecy_and_break_in_recovery` — captured earlier key cannot read the later message without the secret ratchet entropy.
- `test_keys.py::test_session_key_destroy_is_containment` — destroyed key raises on use.
- `test_keys.py::test_capability_token_scope_expiry` — forged / expired / wrong-scope / wrong-key tokens rejected.
- `test_keys.py::test_one_to_one_verification` — wrong handle and biometric-mismatch rejected.
- `test_keys.py::test_no_single_factor_reconstructs_tsk` — impostor biometric + one share insufficient.
- `test_keys.py::test_attestation_precondition_enforced` — recovery refused without attestation.
- `test_keys.py::test_recovery_child_gate_three_attempts` — 3-attempt lockout.
- `test_keys.py::test_context_keys_are_purpose_separated` — domain separation per context.
- `test_liveness.py::test_spoof_stream_does_not_operate` — spoof stream fails the gate.
- `test_liveness.py::test_liveness_break_triggers_suspicious_and_wipe` — break → suspicious + wipe.
- `test_liveness.py::test_reconnect_discriminator` — incoherent reconnect → suspicious.
- `test_crypto.py::test_hybrid_kem_wrong_key_fails` — wrong KEM key → different secret.
- `test_crypto.py::test_hybrid_sign_requires_both_components` — corrupting either component fails verification.
- `test_crypto.py::test_hkdf_combine_unambiguous` — length-prefix framing resists concatenation collisions.
- `test_crypto.py::test_shamir_single_share_is_not_enough` — one share carries no secret bytes.
- `test_crypto.py::test_aead_roundtrip_and_aad` — AAD tamper rejected (the security half).

## Functional tests (correctness, not adversarial)

`test_mode1_normal_encrypted_text`, `test_recover_card_path`,
`test_recover_in_person_path`, `test_identity_tree_structure_and_reproducibility`,
`test_continuity_signed_by_tsk_root`, `test_vault_encrypted_at_rest_and_pqc_wrap`
(round-trip half), `test_live_stream_operates`, `test_attestation_signed_each_step`,
`test_pole_state_has_no_ring_se_sig_but_is_bound`,
`test_voluntary_removal_keeps_ratcheting`,
`test_local_beacon_advances_and_is_stable_within_epoch`,
`test_local_beacon_is_deterministic`, `test_qrng_times_next_sampling`,
`test_qrng_committed_interarrival_timing` (now functional — the real binding proof
moved to the security file), `test_drand_client_against_stub_transport`,
`test_hybrid_kem_roundtrip`, `test_hybrid_sign_verify`,
`test_sign_keypair_deterministic_from_seed`, `test_sphincs_root`,
`test_shamir_2_of_3_all_pairs`, `test_shamir_share_encode_decode`.

## Review findings (code-walkthrough pass)

Two real issues found by reading the code adversarially, both now fixed:

1. **Recognition did not "require both session keys."** It is a DH-style
   agreement: an outsider with neither key can't compute it, but **either
   endpoint's session key + the public wire traffic reconstructs the tunnel**
   (verified empirically). The old `test_recognition_requires_both_keys_*` and
   the module docstring overstated this. Replaced with two honest tests
   (`test_recognition_outsider_without_any_session_key_cannot_compute`,
   `test_recognition_one_endpoint_key_plus_wire_DOES_reconstruct_tunnel`) and a
   corrected docstring stating the real bound. This is the normal 2-party
   agreement bound; forward secrecy + epoch re-keying are what contain it.

2. **Containment left a key copy in RAM.** On a liveness break the `SessionKey`
   object was wiped, but `Device._prev_session_bytes` (the ratchet's prev-key)
   retained an unwiped copy. `_wipe_session` now zeroises it too; the
   containment test asserts it.

## Honest labels that overclaim

- `test_keys.py::test_ratchet_one_way_forward_secrecy` — despite the name, it
  asserts the ratchet **advances** and is **deterministic**, not one-wayness.
  Non-invertibility is an assumption (HKDF/SHA one-wayness), not tested here; the
  attacker-relevant direction is covered by the two forward-secrecy tests above.

## Gaps / assumptions — what is NOT covered

1. **Ratchet non-invertibility** is assumed (HKDF/SHA one-wayness), not
   independently tested (it is not directly testable).
2. ~~**The coupled session-key path** (Math Spec §A) is built but untested.~~ CLOSED —
   `test_coupled_epoch_gaps.py` exercises it: determinism, every-input binding, off-device
   rooting needs the live beacon, distinct from the decoupled construction.
3. **Cross-language interoperability** (Swift `AtlasCore` ↔ Python core produce
   identical bytes) is **mechanized, not yet run on the Mac in this cycle**.
   `parity/parity_vectors.json` pins 23 byte-exact vector categories (incl.
   `recovery_selector`, forensic `signal_digest`/`event_chain`, and the threshold-seal
   `threshold_unlock_key`/`threshold_seal`); Python asserts them
   (`test_parity_vectors.py`, green) and the Swift `ParityVectorTests` asserts the SAME
   file. The residual is running `swift test` on the Mac to confirm the port meets them
   (see VERIFY_ON_DEVICE.md §1) + a runtime ML-KEM/ML-DSA encap-here/decap-there check
   (§2). It is NOT "only SHA3 was checked" — that line predated the vector suite.
4. **Real PQC backends** (liboqs / CryptoKit) are untested here. Tests run
   against pure-Python ML-KEM-768 / ML-DSA-65 + a real SPHINCS+ wheel. ML-DSA/
   ML-KEM standardisation drift and CryptoKit API names must be verified on the
   Mac.
5. **Device attestation** (App Attest / DeviceCheck / Secure Enclave) is a
   boolean stub in recovery tests, not exercised against real hardware.
5a. **Recovery is stratified**: device-present paths (card, in-person, normal auth)
   use Secure Enclave robust biometric release; the **total-loss** path recovers from
   the two portable threshold shares (card + context) with NO Enclave and NO biometric —
   the anti-spoof there is the live, accountable recovery person of the in-person
   ceremony (`realid.recovery_anchor`). The fuzzy extractor is RETIRED (TRUST_LAYER.md #7):
   Atlas extracts no key from raw biometrics and stores no biometric sketch.
6. **Liveness** is tested on **synthetic** streams with heuristic likelihoods —
   no real PPG/accelerometer. Population-scale Sybil / anti-farm / density (§11)
   are explicitly out of scope (needs a campus pilot).
7. **Anti-replay is structural** (stale tunnel key fails AEAD), not an explicit
   nonce/replay-cache. Within-epoch replay is allowed by design (§4). The
   **epoch-cap runtime guard** is now ENFORCED + TESTED (`session/epoch_guard.py`,
   `EpochCapGuard`): if the beacon has not advanced within `EPOCH_LENGTH_CAP_S` the
   epoch is stale and `check()` raises `EpochStalled` to force a re-key (fail-closed —
   an un-bootstrapped guard is expired). `test_coupled_epoch_gaps.py`.
8. **Constant-time / side-channel** behaviour is not evaluated (pure-Python is
   not constant-time). HMAC/`compare_digest` is used for token checks; broader
   timing-safety is out of scope for the bench PoC.
9. **Mode-2 after first authorized view** — a legitimate verified viewer can
   screenshot. By design (§9.2), not a defect; not "prevented".

These are the items an independent red-team / audit (§11, against the frozen
spec) should target. The suite raises the floor on correctness and on the
tier-1 protocol properties; it does not substitute for that audit.
