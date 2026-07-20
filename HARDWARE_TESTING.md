# Atlas PoC — Hardware Testing & Red-Team Runbook

The bench proved the **protocol mechanism** in simulation with real crypto
primitives. This runbook covers the part the bench **cannot** answer:
everything that touches real hardware and a real human. It exists so the kit is
testable the day it's assembled, and so "working" has a **measurable
definition** for each seam — not a hopeful wiring-up.

How to read it: Phase 0 is bring-up. Then per-milestone functional exit tests
(§13). Then the **Real-World Seam Criteria** — the core of this document — which
give, for each thing sim couldn't prove: what sim *did* prove, what's still
unproven, the on-hardware procedure, the **PASS threshold**, and the **honest
expected failure mode**. Then the adversarial red-team battery (§9.5) and a
results table to fill in.

> Honesty rule for this runbook: a seam is "passed" only when it meets the
> stated numeric threshold on hardware. "It ran without crashing" is not a pass.
> Where we expect the current implementation to fail, that is written down — the
> point of the hardware phase is to close exactly those gaps.

---

## Kit (per spec §1.1)

- MacBook (Python verifier/beacon/QRNG + Xcode build host)
- 2× iPhone 17 Pro Max (wallet pair)
- 2× Colmi R10 rings
- JavaCard (dual-interface) + reader
- BLE sniffer (e.g. nRF52840 + Wireshark) and a LAN proxy (mitmproxy/Wireshark)
- A screen + a printed photo + a short video, for the PAD spoof battery

---

## Phase 0 — Bring-up (do this first; mostly automatable)

| Step | Action | PASS criterion |
|------|--------|----------------|
| 0.1 | `cd backend && pip install -r requirements.txt && python -m pytest` | 74/74 green |
| 0.2 | Re-generate parity vectors: `python -m tools.gen_parity_vectors` | writes JSON to backend + Swift test bundle |
| 0.3 | `cd ios/AtlasCore && swift build` | compiles with **0 errors** (resolve the flagged PQC/SLH-DSA/SHA-3 API seams) |
| 0.4 | `swift test` (runs `ParityTests`) | **every parity vector reproduces byte-for-byte** |
| 0.5 | Replace `PlaceholderSphincs` with a real SLH-DSA/SPHINCS+ provider | TSK continuity sig verifies on device |
| 0.6 | Wire the bench harness (Mac logger + phone diagnostics screen) | structured events from both phones reach the Mac log |

**Phase 0 is the gate.** Until 0.3/0.4 pass, the iOS crypto is *unverified
source*. ParityTests passing is the definition of "the Swift core is correct".

---

## Functional milestone exit tests (§13)

Drive these from the harness; assert against the merged Mac log.

- **M1** — two phones + Mac beacon/QRNG. Send encrypted text A→B; send a 2nd
  message; send both in Mode 1 and Mode 2.
  **PASS:** B displays both; the 2nd uses a ratcheted key; Mode-2 message opens
  only when B is verified-live + on-network.
- **M2** — pair a real R10; issue the real-time stream command; consume the
  notify stream.
  **PASS:** live HR/SpO2/accel decode at the documented packet format; the
  biology-timed ratchet fires; **removing the ring mid-session wipes the session
  key and blocks a value action within ≤ 3 s** (containment).
- **M3** — run the in-person enrolment ritual (TrueDepth/IR + fingerprint +
  co-motion tap challenge correlated with ring accel + secret construction).
  **PASS:** one bound session yields the full tree + helper data + 2-of-3 shares;
  a remote-enrolment attempt is **rejected**.
- **M4** — recover on an attested device: card path (JavaCard share + live
  biometric) and in-person forward-recovery.
  **PASS:** full tree reconstructed; **wrong biometric and missing attestation
  both refuse** (see seam (b) for the real-biometric caveat).
- **M5** — capture a real photo (LiDAR); sign earliest frame; send to B.
  **PASS:** B verifies author + time + integrity + PAD + anchor; **a screen
  replay is rejected by PAD at capture** (see seam (d)).
- **M6** — Mode-2 message to B.
  **PASS:** opens live+on-network; **denied** when B is offline (airplane mode),
  on a stolen device, or driven by a script.

---

## Real-World Seam Criteria (the heart of this runbook)

Each seam: what sim proved · what's unproven · procedure · **PASS** · **honest
expected failure**.

### (a) Swift compiles + cross-impl parity
- **Sim proved:** the Python core is internally consistent; SHA3 matches `hashlib`.
- **Unproven:** the Swift core has never compiled; Swift↔Python byte-agreement.
- **Procedure:** Phase 0.3–0.4.
- **PASS:** `swift build` clean **and** all `ParityTests` vectors reproduce
  byte-for-byte (SHA3, HKDF, AES-GCM, ratchet, session key, recognition/X25519,
  tunnel, handle, ledger, PAD, token MAC, canonical metadata).
- **Expected failure:** the flagged CryptoKit PQC names / SLH-DSA seam / SHA-3
  substitution. A parity miss localizes the diverging byte to one derivation.

### (b) Biometric recovery — STRATIFIED (Enclave device-present vs portable-share total-loss)
Recovery uses each mechanism where its property fits (`atlas/keys/recovery.py`):
device-present paths (card, in-person, normal auth) release `share_bio` via the
Secure Enclave (robust match, device-bound); the total-loss path recovers from the two
PORTABLE shares (card + context) with no Enclave and no biometric. Test them separately.
*(The fuzzy extractor is RETIRED — TRUST_LAYER #7 — so there is no biometric-sketch
hardware test; the total-loss path is pure Shamir combine gated by the in-person ceremony.)*

**(b1) Device-present — Secure Enclave biometric release (the PoC demo path)**
- **Sim proved:** a robust matcher accepts realistically-noisy casual reads; the sealed
  share is device-bound; the biometric is never exposed.
- **Unproven:** real Face ID/Touch ID gating of the SE key on device.
- **Procedure:** enrol; recover via card + in-person across ≥ 30 fresh reads per
  user (varied lighting / finger placement); run impostor reads.
- **PASS:** **FRR < 2 % (Apple's matcher) at FAR < 0.1 %** over ≥ 30 genuine and
  ≥ 30 impostor trials per user; the SE key release prompts biometrics and the
  biometric never enters app code.
- **Honest note:** this trusts Apple's matcher + device hardware as the gate
  (fine, and more robust than rolling our own) and is **device-bound by design**
  — it is *not* the total-loss path (see b2). This is the path to demo now; it
  unblocks recovery on real fingers.

**(b2) Total-loss — the two PORTABLE shares (catastrophic, no Enclave, no biometric)**
- **Sim proved:** recovery on a fresh device from the card + context shares (2-of-3),
  by construction (no Enclave argument) never depends on the lost device; no biometric
  is involved.
- **Unproven (hardware):** the operational **in-person recovery ceremony** — a live,
  accountable recovery person verifying the claimant + the backend releasing the context
  share only under that ceremony. That is a *procedural/human* control, not a crypto test.
- **Procedure:** simulate total loss; recover on a fresh device from the card share +
  the context share, released under a witnessed in-person ceremony.
- **PASS:** the TSK is reconstructed from the two portable shares with **zero dependence
  on the original device's Enclave** (verified by the device being absent), and the
  context-share release is gated by the (mock, then real) in-person ceremony.
- **Honest note:** there is **no biometric sketch to fail here** — the fuzzy extractor is
  retired (TRUST_LAYER #7). The residual risk is entirely in the *ceremony* (impersonation
  of the claimant to a recovery person), which is why total-loss is rare, in-person, and
  accountable. Device-present (b1) remains what works on a finger today.

### (c) Liveness gate on REAL PPG
- **Sim proved:** the Bayesian gate separates *synthetic* live vs spoof streams
  with a heuristic likelihood.
- **Unproven:** behaviour on real HRV/accel distributions from the R10.
- **Procedure:** ≥ 20 live sessions (varied users, rest/post-exercise) + a spoof
  battery: ring-off, static replay of a recorded PPG stream, video-of-pulse,
  warm inanimate object.
- **PASS:** live reaches **P(L|S) ≥ π\*=0.95 within ≤ 10 s in ≥ 95 % of live
  sessions**, and **no spoof in the battery ever reaches π\***.
- **Honest expected failure:** the synthetic likelihoods (`Synthetic.likelihood`)
  and π\* will need **recalibration on real data** — the heuristic won't transfer
  unchanged. Expect to fit `P(S|L)`/`P(S|¬L)` from a labelled real corpus and
  possibly add HRV-from-inter-beat-interval features. Until recalibrated, treat
  the gate as *uncalibrated*.

### (d) PAD on a REAL screen / depth map
- **Sim proved:** a flat depth map (variance < 0.01) is rejected; a varied one
  passes; high moiré is rejected.
- **Unproven:** behaviour on real LiDAR depth and real camera frames.
- **Procedure:** spoof battery — phone screen, external monitor, printed photo,
  video on a tablet — at 20/40/60 cm and ±30° angles; plus ≥ 30 real-scene
  captures for the false-reject rate.
- **PASS:** **≥ 95 % of flat-screen/photo replays rejected** at a **false-reject
  rate < 5 % on real scenes**; tune the depth-variance threshold on real LiDAR
  (the 0.01 m² bench value is a placeholder).
- **Honest expected failure:** PAD is probabilistic, **not proof** (§8.2). A
  curved display, a high-quality 3-D mask, or sub-OS sensor injection can defeat
  it; the analog hole remains. The claim is scoped to "catches the majority of
  screen replays," and the real moiré detector (frequency-domain) still needs to
  be built — the device stub returns a fixed low score.

### (e) Containment on real hardware
- **Sim proved:** a liveness break wipes the session key *and* the ratchet
  prev-key; a destroyed key raises on use.
- **Unproven:** that this fires on a real ring-removal / real seizure, end to end.
- **Procedure:** mid-session, (i) pull the ring, (ii) fail liveness, (iii) lock +
  seize the phone. Inspect via the harness that RAM key material is gone.
- **PASS:** in **100 %** of trials, the session key is wiped and a liveness-gated
  action is blocked **within ≤ 3 s**; a Mode-2 message becomes unopenable.
- **Honest expected failure:** OS memory hygiene (key bytes lingering in freed
  pages, swap, or a snapshot) is below what app code controls — note it for the
  audit; the Secure-Enclave-resident path is the mitigation.

### (f) Real device attestation (App Attest / DeviceCheck / Secure Enclave)
- **Sim proved:** the *software-side* of the attestation now holds — the
  attestation is a hybrid ML-DSA+Ed25519 signature over (epoch, PoLE decision,
  **fresh verifier challenge**), so a relying party gets key-possession +
  freshness + key-binding (Mode-2 pins `H(enclave_public)` and demands a
  signature over a challenge it picks at open time; captured attestations are
  refused — see `test_session.test_mode2_rejects_replayed_stale_attestation`).
- **Unproven (the hardware trust anchor):** that the signing key genuinely lives
  in a non-extractable, biometry-gated Secure Enclave on un-modified hardware,
  rather than an extracted/software key — i.e. that a genuine device is accepted
  and a tampered one refused. This is the part the software deliberately does
  **not** fake (no stub attestation CA).
- **Procedure:** run enrolment + recovery on (i) a stock device, (ii) a
  jailbroken / re-signed / modified build.
- **PASS:** stock accepted; **tampered build refused 100 %** for both enrolment
  and every recovery path.
- **Honest expected failure:** App Attest proves the *protocol* on a stock OS; it
  does **not** prove sovereignty (Tier-3 limit, §1.1) and can be undermined on a
  fully compromised OS — that's the audit's call, not a unit test's.

### (g) BLE leakage (the R10 is an untrusted, open sensor — §0.3)
- **Sim proved:** the phone encrypts the raw stream under the DevKey on receipt.
- **Unproven:** that nothing sensitive actually leaves the phone boundary, and
  that replayed ring packets can't forge liveness.
- **Procedure:** sniff the R10↔phone link for ≥ 10 min of live use; separately
  replay captured raw ring packets into the phone.
- **PASS:** **zero raw-biometric frames cross the phone's trust boundary** (only
  the DevKey-encrypted envelope leaves the BLE handler); replayed raw packets
  **do not** drive `P(L|S)` to π\* (the co-motion binding + Bayesian gate reject
  stale/forged streams).
- **Honest expected failure:** the R10 link itself is plaintext by design
  (open BLE) — anyone in range reads raw HR. That's the *threat model*, not a
  bug: the phone, not the ring, is the trust boundary, so confirm the boundary
  holds rather than expecting a private ring link.

### (h) Wire / transport properties on the real network
- **Sim proved (unit level):** no session key crosses the wire; stale recognition
  is inert after the beacon advances; later keys can't read earlier ciphertext.
- **Unproven:** the same over the real phone↔phone / phone↔Mac transport.
- **Procedure:** capture traffic; attempt (i) session-key extraction, (ii) replay
  a captured recognition/tunnel after a beacon advance, (iii) decrypt epoch *e−1*
  with an epoch *e* key.
- **PASS:** no session key observable on the wire; replayed recognition
  **rejected**; prior-epoch ciphertext **undecryptable** with a later key.
- **Note (corrected claim):** recognition is a 2-party DH agreement — an outsider
  can't compute it, but **compromising one endpoint compromises that pairwise
  tunnel**. Test outsider-resistance + forward secrecy, not "needs both keys".

### (i) PQC interop (ML-KEM / ML-DSA across implementations)
- **Sim proved:** each library's primitive works in isolation (pure-Python core).
- **Unproven:** CryptoKit (Swift) ↔ liboqs/pure-Python (Mac) interop.
- **Procedure:** encapsulate on Swift / decapsulate on Python (and reverse); sign
  on one / verify on the other, over ≥ 100 random trials each direction.
- **PASS:** **100 %** success both directions. (This is runtime interop, not a
  static vector — keygen is randomized.)
- **Honest expected failure:** the X-Wing-style combiner must be **identical** on
  both ends; if you adopt CryptoKit's native `XWingMLKEM768X25519`, switch the
  Python core to the RFC X-Wing combiner too, or interop breaks.

### (j) Power budget — battery drain over a real day
- **Sim proved (model only):** the cost *structure*, not Joules. The crypto is
  cheap (lattice KEM/sign are sub-ms on Apple silicon; SPHINCS+ is root-only).
  The recurring cost is the **continuity ratchet cadence** + the always-on radios.
  The device ratchets on its OWN 10s ± biological-jitter clock
  (`params.RATCHET_NOMINAL_S` / `RATCHET_JITTER_S`, independent per device), and
  per the locked model consumes each beacon **FRESH** at its tick — **no cache**
  (`continuity_tick(..., beacon=...)`); a stale/absent beacon is fail-closed
  (inert), never folded. One local wake per ~10s: ring sample + ratchet + one
  ML-DSA+Ed25519 attestation. NOTE (trade-off): removing the beacon cache means
  the ratchet's beacon must be current, so the radio/beacon path is exercised on
  the device cadence rather than amortised across a 30s cache — measure the
  resulting radio-on time on device; the independent-clocks model (device 10s,
  LK 30s, epoch ~1min) is what bounds it.
- **Unproven:** actual %/hour on a real iPhone + R10 over a day of mixed use.
- **Procedure:** instrument with Xcode Energy Log / `MetricKit` over ≥ 4 h each in
  (i) **idle** (no active session, epoch backed off toward `EPOCH_LENGTH_CAP_S`,
  ring connected), (ii) **active session** (Mode-2 viewing / payments, epoch at
  the floor). Measure device draw, radio-on time, and BLE connection-interval.
- **PASS (set with product):** e.g. **idle < ~2 %/hr** incremental over the ring's
  own baseline, **active < ~8 %/hr**; no wake-storm when many devices are
  co-present (per-device **biological** jitter desynchronises them).
- **Honest expected failure:** the dominant drain is the **persistent BLE + PPG
  stream** and any **uncoalesced beacon polling**, not the crypto. If idle drain
  is too high, the levers are: lengthen the idle epoch, duty-cycle the ring, widen
  the ratchet period/jitter, and coalesce beacon fetches onto the wake — *not*
  cheaper signatures.

---

## Red-team / spoof-completeness (§9.5 — external)

The bench reaches **tier 1 only** (per-instance protocol). A complete spoof
requires *simultaneously*: the enrolled ring on the enrolled finger, the enrolled
wallet, all devices passing live attestation, the correct tap challenge, the
ending pattern, the right (non-canary) finger, a healthy PoLE with authentic
cardiac signals, and no duress markers — i.e. the enrolled human, present, calm,
voluntary. Hand the **spoof-completeness claim** to an external red-team (NCC
Group, Trail of Bits) against the **frozen spec** (params in `atlas/params.py`).
Bench red-teaming should attempt each *single* factor (replay one channel, fake
one signal) and confirm the stack rejects it; the *simultaneous* completeness is
the paid external step.

---

## Out of bench scope (needs a pilot, not a kit)

Real Sybil resistance, anti-farm economics, and density/colocation (§11,
"Population-scale human") **cannot** be tested on two phones. They need a campus
pilot with real people. The bench proves the mechanism; the population claim
needs population.

---

## Results table (fill in on the kit)

| Seam | PASS threshold | Result | Notes |
|------|----------------|--------|-------|
| (a) Swift compile + parity | parity 100 % | | |
| (b1) Enclave device-present recovery | FRR<2% @ FAR<0.1% | | the demo path; works on real fingers |
| (b2) portable-share total-loss recovery | TSK rebuilt from card+context, no Enclave | | risk is the in-person ceremony, not crypto |
| (c) liveness real PPG | live≥π* in 95%; spoofs<π* | | expect: recalibrate likelihoods |
| (d) PAD real screen | ≥95% replays rejected, FRR<5% | | expect: build real moiré detector |
| (e) containment | 100% wipe ≤3s | | |
| (f) attestation | tampered refused 100% | | |
| (g) BLE leakage | 0 raw frames past boundary | | |
| (h) wire properties | replay rejected; FS holds | | |
| (i) PQC interop | 100% both directions | | |
| (j) power budget | idle<~2%/hr, active<~8%/hr | | fresh beacon per tick (no cache); measure radio-on; tune BLE, not crypto |
| M1–M6 exit tests | per §13 above | | |
