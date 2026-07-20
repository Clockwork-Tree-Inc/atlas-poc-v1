# Atlas PoC — decisions log

Settled choices from the working sessions, so nothing is silently re-litigated.
Reference the source specs (ATLAS XIV.5, Math Spec v1.4, System Architecture,
`PoC_Code_Spec_Provenance_Binding.md`) for the full rationale.

## Identity

- **A4 — System-ID handle derivation: PER-CONTEXT DERIVED HANDLES.**
  A distinct hash-chained handle per context/use (true identity unlinkability,
  required for the anonymity tier). The identity tree already derives per-context
  children (`CHILD_CONTEXTS`, `pseudonym(label, tier)`); this is the consistent
  direction, not the single static `H(TSK_public)`.
  - **Intended rotation trigger:** disconnect + re-enroll on a liveness break
    (re-roots the System-ID; pseudonyms re-derive). DEFERRED for the phone-only
    ambient build — there is no biological liveness-break signal without the R10
    ring, so the ambient PoC does not rotate on break yet. Wire this when the ring
    lands (the source swap that turns "signal present" into "living human present").

## Recovery

- **C4 — failed-recovery lockout: GRADUATED ESCALATION TO IN-PERSON.**
  Every attempt logged from the first wrong try (no free retries); each failure
  escalates scrutiny/delay, ending at required in-person recovery at a certified
  institution. Not a hard 3-strikes lockout (lower false-lockout risk for
  legitimate users; matches the corpus lean toward graduated response).

## Messaging / relay

- **Phone↔phone is END-TO-END; the Mac node is a BLIND RELAY.** The two phones
  share an A-B key the node never holds; the node stores/forwards opaque
  ciphertext it cannot read. A separate OPT-IN public path (verify + anchor) is
  used only for content the user deliberately publishes.
  - Honest boundary: content is E2E-private; the relay still sees ENVELOPE
    METADATA (from/to mailbox, size, order). Sealed-sender / mixing / cover-traffic
    is the documented upgrade path, not built.

## Ambient iPhone PoC

- **Ambient sensors TIME and GATE; QRNG VALUES.** Sensor bytes never enter a
  key/value. Value stays clean QRNG.
- **Fresh-per-tick, on-demand (B4):** the ambient source is pulled once per
  ratchet tick, not run continuously.
- **Source-agnostic:** the ring swaps in for the ambient source with no pipeline
  change (`AtlasFlags.signalSource = .ring`).

- **Ambient signal is CHANGE-BASED, not level-based (XOR vs previous snapshot).**
  Each fused snapshot is XOR'd against the previous one (raw — noise and
  everything). The baseline cancels, so absolute level (e.g. loudness) stops
  mattering; only CHANGE drives presence + cadence. A frozen/replayed-identical
  snapshot flips ZERO bits -> fail-closed. Mic KEPT (all channels), but only its
  change counts; audio session uses `.mixWithOthers` so sampling it no longer
  interrupts the user's music (the orange indicator still shows — mic IS briefly
  on; no audio recorded/stored).
- **Entropy ACROSS SNAPSHOTS: Shannon (quality) + min-entropy (hard gate).**
  Snapshots are symbols; Shannon grades diversity (feeds the Bayes gate),
  min-entropy (worst-case) hard-gates a short A,B,A,B replay loop that XOR alone
  waves through. Hard gate applies only at a FULL buffer (stable threshold);
  catches short (<=~5-frame) loops — a long recorded replay still needs the ring's
  biological coherence. These are MEASUREMENTS that only time/gate — never a value.
- **Ambient change DRIVES the PoLE liveness** (replaces the synthetic stand-in):
  each tick's change/entropy maps to Bayesian evidence folded into a persistent
  gate. Seeded at enrol (Face-ID-proven presence) so the first ratchet operates;
  a frozen/looped feed then erodes it -> fail-closed. Device wiring
  (`AtlasRuntime.ambientPoLE`) is verified on-device; the mapping + gate are
  reference-of-record in Python and parity-tested in Swift.
- **GBSS entropy vector (Math Spec v1.4): liveness scored, never keyed.** Liveness
  is assessed as a vector — h_i (HRV/PPG/GSR, involuntary, RING-deferred), s_i
  (IMU), m_i (touch/keystroke/voice), c_i (ambient) — each scored by the entropy
  operators (Shannon, Lempel-Ziv complexity, spectral entropy; + min-entropy) into
  a per-channel density, aggregated into a per-window liveness density that feeds
  the PoLE gate. On the phone h_i is None (ring-deferred; the phone cannot produce
  the involuntary biomechanical core); the density covers only present channels.
  INVARIANT: every operator/density is a MEASUREMENT that only gates/times — none
  is folded into a key/value. "Entropy proves life; QRNG is the value." Reference-
  of-record in Python (`liveness/entropy.py`, `liveness/gbss.py`), parity-tested in
  Swift (`Liveness/Entropy.swift`, `GBSS.swift`).

## Naming / glossary

- **NAMING.md is the canonical vocabulary** (single source of truth). It fixes three
  overloads that caused real confusion: "epoch key" (public **epoch id** label vs the
  secret network-aggregated **epoch key** that wraps the LK); "the ratchet" (**message
  ratchet** — per-message FS, vs **continuity ratchet** — ambient-timed epoch
  advance); and "LK" (single-device **stub** vs **co-derived** Living Key). Canonical
  model: the epoch key is a per-epoch QRNG sampled by aggregating current LKs across
  LKG regional nodes; the LK is system-wide private, unwrappable only with the current
  epoch key (presence-gated). Prototype stubs: local RNG for the regional aggregation,
  N=2 co-derivation as the stand-in, device RNG for QRNG. Optional code rename
  (epochKey → epochWrapKey; label the two ratchets) deferred until the two subsystems
  are composed, so it happens once.
- **R10 ring wired as the coherent-biology liveness anchor.** `RingSignalSource` now
  consumes a ring sampler (real R10 on device; injected `SensorSample` stream in
  tests) and produces the same `LiveSignalSample` as ambient — the source swap with
  no pipeline change. `simulated=false` (the honesty flip vs the ambient stand-in). A
  removed/absent ring or an incoherent pulse (flat HRV / spoof) reads as ABSENT ->
  fail-closed (the liveness-break signal ambient lacked); with NO sampler it refuses
  (won't fake biology). The ring's HRV populates the GBSS **h_i** channel (the
  involuntary core the phone cannot produce): `ring_h_i` blends HRV AMPLITUDE
  (healthy ~tens of ms vs single-digit flat/spoof) with interval COMPLEXITY — low
  unless both hold. Honest boundary: a high-amplitude complex REPLAY needs the ring's
  own on-body anti-spoof, not this score. Invariant intact: biology times/gates,
  never a value. Reference-of-record + Swift parity (ring_h_i vectors, timing).

## Hardware factors

- **Role separation (holds across all factors).** The always-worn, easily-lost RING
  holds NO secrets (liveness only; removal -> fail-closed). The deliberate,
  rarely-touched YUBIKEY and USB hold the secrets. Never put secrets on the ring.
- **YubiKey Bio = the high-stakes factor.** A non-extractable key signs a high-risk
  action (recovery / identity rotation / transfer) gated by the YubiKey's OWN on-key
  fingerprint; the signature binds (action, context, fresh challenge) so it can't be
  replayed onto another action. May also hold a recovery Shamir share, released only
  on the same fingerprint. Fail-closed. Real key/fingerprint = YubiKit; reference
  models it with Ed25519.
- **USB DualDrive = the recovery factor (replaces the card).** Carries the
  `share_card` 2-of-3 Shamir vertex, KEM-wrapped to the recovery key: a LOST DRIVE IS
  OPAQUE (only the recovery key reads it) and ONE SHARE CANNOT reconstruct (needs
  k-of-n). Restores CONTROL via the identity system even if the drive is lost. JSON
  blob format is portable phone<->Mac.
- **Payments no longer need a side button.** The Payment spec always called the
  side-button press a "YubiKey-touch replacement" (it lacks separate-device
  isolation, and iOS blocks the button for third parties). Now that the YubiKey Bio
  factor exists, its fingerprint-on-key signature over THIS transaction IS the
  deliberate intent: `yubikey_intent.intent_from_yubikey` verifies a YubiKey
  authorization bound to (descriptor, card nonce) and mints the IntentToken the
  arming authority consumes. Fail-closed (no fingerprint -> no signature -> no
  intent -> no arming); the signature binds the exact amount/descriptor (no swap)
  and the card nonce (no replay). Strictly stronger than the button.

## Authentication (product framing)

- **Atlas is an AUTHENTICATOR, not a bank / wallet / payment rail.** It authenticates
  a PERSON to a relying party (a bank, a service, anything): proves "a verified, live,
  present human — optionally with a YubiKey step-up — authorized THIS action", and
  hands that proof to whoever runs the actual system. Passkey/WebAuthn-shaped
  (register a key, answer a challenge) but far stronger: liveness + presence + optional
  hardware step-up, bound to the relying party (relay/phishing-resistant), fail-closed.
  `auth/relying_party.py`: AuthChallenge -> authenticate -> VerifiedHumanAssertion ->
  verify_assertion. (The earlier in-vault "banking app" direction was dropped — Atlas
  gates access, it is not the account.)
- **Hardware factors, final roles:** RING = liveness (no secrets). YubiKey = the
  high-stakes / step-up authorizer (fingerprint-on-key). USB = recovery-only (encrypted
  Shamir share). CARDS = a FUTURE, AIR-GAPPED extra-strength factor for the SHIPPED
  product (a separate network-isolated signer) — not built now.
- **"Face-ID+": Atlas is a PASSKEY PROVIDER, not a replacement for the OS Face ID.**
  You cannot inject Atlas into another app's `LocalAuthentication` (Apple-locked). The
  realistic path is passkeys/WebAuthn — iOS 17+ lets a third-party app be the
  credential/passkey provider. Atlas registers as one; a passkey-supporting bank uses
  it with NO code change; underneath, the passkey signature is produced only AFTER
  Atlas's gate (live presence + optional YubiKey step-up). Same interface as a passkey
  / Face ID, a much stronger authenticator behind it. Our AuthChallenge/assertion is
  already WebAuthn-shaped (RP-bound = origin binding); the device work is the
  ASCredentialProviderExtension + mapping the assertion to WebAuthn (HANDOFF_AUTH.md).
  Honest boundary: the bank must support passkeys (growing) + the user picks Atlas;
  non-passkey banks need an SDK. Atlas can't override every bank unilaterally.

## The intent gesture (the "side-button press")

- **The YubiKey was never a card substitute — it is a SIDE-BUTTON-PRESS substitute.**
  Apple Pay's double-click confirms deliberate human intent to authorize THIS action
  (hardware-attested, malware can't fake it). That is the "intent gesture": identity-
  independent ("yes, do this, now"), distinct from ambient/ring liveness (who / alive).
  The YubiKey fingerprint modelled exactly that gesture.
- **The literal iPhone side button is unavailable to us.** Apple reserves the
  double-click-to-confirm sheet for PassKit/Apple Pay; a third-party app cannot summon
  it for a general authorization (same wall as the payment rail).
- **The iPhone intent gesture is a per-ACTION Face ID / Touch ID confirm** whose prompt
  names the exact action — the one deliberate, Secure-Enclave-attested confirmation iOS
  hands a third party. `AtlasApp/Auth/IntentGesture.swift`; wired at Recovery (userHalf
  is not released without it), fail-closed. This ships today and needs no extra hardware.
- **YubiKey Bio can't produce the gesture on iPhone** (USB-only, no NFC; iOS FIDO2 is
  NFC/Lightning). The Bio stays a desktop factor; an NFC key (5C NFC) could serve as a
  detached tap-gesture on the phone later. The auth primitive
  (`HighStakesRequest` → sign → `verifyHighStakes`) is factor-agnostic, so the physical
  gesture swaps per platform with no protocol change.
- **Honest boundary / follow-up:** Face ID is currently the real *gesture*; the step-up
  *signature* is still modelled. To bind the signature to the gesture, promote the
  signer to a biometry-gated `SecureEnclave.P256.Signing` key + a P-256 step-up parity
  path in AtlasCore (HANDOFF_HARDWARE.md §2).

## Recovery anchor — the real you, unlinked from the digital you

- **The recovery pseudonym is the anchor of the REAL you (your face), cryptographically
  unlinked from the DIGITAL you.** The digital you IS the System-ID (derived from the
  TSK) — the blind root that generates all children/pseudonyms. Enrolment binds your
  biometric AGAINST the recovery pseudonym; the bridge back to the System-ID is sealed
  and stored under it. The total-loss anchor restores the System-ID (children regenerate
  from it), NOT the full TSK — the master root additionally needs the token half (Half B:
  wallet + YubiKey). A breach of the biometric store reveals faces bound to opaque
  pseudonyms, never which digital identity each is — and vice-versa. Recovery is the only
  bridge, and it is ceremony-gated. (`realid/recovery_anchor.py`.)
- **Your NAME is your username; the PASSWORD only differentiates you from namesakes.**
  The selector is `H(name, scrypt(password))` — the password is NOT a secret and NOT a
  security gate; it exists solely so two people who share a name resolve to different
  records (same name + different password -> different record). This gives a DIRECT 1:1
  lookup instead of a privacy-toxic 1:N biometric search. Because the selector is a pure
  function of (name, password) — independent of the System-ID — it leaks nothing about
  the digital you. The real identification + security are the recovery PERSON (sees your
  face) + breeder documents + biometric 1:1 match + threshold; the password's low entropy
  is irrelevant because it gates nothing. In the escalated/total-loss path the password
  is a minor check (documents/the person locate + attest); in routine paths (have wallet,
  lost YubiKey, calm — "like losing a credit card") it carries more weight. Duress /
  suspicious / emergency escalate to the human-attested path. [escalation router: TODO]
- **Total-loss (rung 3) factors, all AND-ed, all fail-closed:** password selector (know)
  → biometric 1:1 MATCH (are) → live recovery PERSON who sees your face + signs (vouch)
  → n-of-x servers (have). **Server access alone is inert** — the bridge is sealed under
  (biometric ∧ threshold) and will not release without the witnessed signature; a full
  n-server collusion without the live human gets nothing.
- **The recovery person supplies the liveness**, so a plain SE computer (no ring/ambient
  sensors) is a valid recovery terminal. **Devices enrol on Secure Element presence;
  liveness is a capability flag, not an enrolment gate** (`DeviceCapability`).
- Reuses vetted primitives only — `crypto/shamir` (n-of-x), `hashlib.scrypt` (memory-hard
  selector, Argon2id stand-in), `keys/hardware_key` (witness signature). No hand-rolled
  crypto. (The fuzzy extractor was later RETIRED — TRUST_LAYER.md #7 — so no biometric
  sketch is stored; the face check is the Secure Enclave or the live recovery person.)
- **Follow-ups:** drand-labeled per-half System-ID auto-ratchet; the token rungs (1: wallet
  + server; 2: YubiKey Bio in-person at any Atlas-network SE computer) building on the
  existing `recover_via_card` path; Swift port + Mac-node `/recover` endpoint.

## Forensic ledger — every decision recorded, and the substrate for suspicion

- **Every login / high-stakes / recovery / payment decision leaves a vault-sealed
  forensic event** (`session/forensic_ledger.py`). Each event is HASH-CHAINED (drop /
  reorder / alter breaks the chain), SIGNED by the device key (forgery fails verify), and
  AEAD-SEALED into the vault (opaque at rest; the subject handle isn't readable). It logs
  the outcome AND the risk — allow / deny / escalate — so the log both audits and feeds
  the next assessment. The event carries a pseudonym/handle, never the digital-you
  System-ID directly (unlinkability preserved). Complements `session/forensic.py` (the
  alarm-triggered capture WINDOW) and `liveness/attestation.py` (liveness-break SUSPICIOUS).
- **Suspicious activity is classified from signals** (`assess_risk`): sudden liveness loss,
  strange login attempts (new device, impossible travel, off-hours, repeated failed
  factors) -> SUSPICIOUS; duress -> DURESS; total loss -> EMERGENCY; else ROUTINE. Highest
  applicable level wins (fail-closed toward escalation). ROUTINE -> allow; anything
  elevated -> escalate (to the human-attested recovery path); failed factors -> deny.
- **Invariant:** the ledger GATES/audits and TIMES; risk is a policy signal, never entropy,
  never enters key material.
- **Follow-up:** wire `assess_risk` into the recovery paths (routine password-led vs
  escalated human-attested) + breeder-document commitments — the escalation router the
  recovery section flagged as TODO.

## Ring: use the whole IMU, not just PPG

- **The ring is more than a heart-rate sensor.** PPG gives the involuntary pulse (h_i);
  the IMU (accel; the R0x has no gyro) gives motion (s_i) AND two things we were leaving
  on the table:
  1. **Cross-channel coherence (anti-spoof):** the heartbeat appears in PPG rate, HRV,
     AND the accelerometer ballistocardiogram; on a live finger they agree. A replay that
     fakes PPG but not a phase-aligned accel BCG fails coherence — faking all channels
     coherently is exponentially harder. [build: multi-sensor h_i + coherence gate — TODO]
  2. **Motion as a soft biometric (the population-scale Sybil lever):** general IMU
     movement — gait, walking, daily activity — is DISTINCTIVE per person. Sybil
     resistance at scale needs distinctness (these are different people), not just
     liveness. Measured on the real 24 MotionSense subjects, a crude motion signature
     re-identifies people at **~8x chance** (`atlas/sim/motion_biometric.py`), and a
     smarter replay farm that jitters one person's motion across identities still
     COLLAPSES to one (they collide on the gait signature). Honest boundary: SOFT
     biometric on mixed-activity data — a distinctiveness/anti-duplication LAYER, not
     standalone ID; per-activity gait features + a pilot raise the ceiling.
- INVARIANT intact: every sensor MEASURES to gate/dedup liveness+distinctness, never
  enters a key/value.

## Phone <-> ring cross-referencing (same-body binding)

- **The phone IMU and the ring IMU should agree.** On one live body they share the body's
  motion, so their streams CORRELATE (at a small lag). `liveness/cross_device.py`
  (`cross_correlation`, `same_body`) gates on it. Measured on real MotionSense streams:
  same-body ~0.95 (lag-tolerant), detached/idle ring ~0.00, different person ~0.05 — floor
  0.4 separates cleanly. Two jobs at once: anti-spoof (a ring not moving with you fails)
  and same-body binding (ties THIS ring to THIS phone to ONE body; defeats ring-on-A /
  phone-on-B farming — an attacker must fake mutually-correlated multi-device motion).
- Honest boundary: wrist vs pocket differ, so correlation is strong not perfect; the floor
  is a heuristic, re-tuned on-device. Feeds the GBSS coherence gate; measures, never keys.

## Cross-channel coherence + closed review gaps

- **Cross-channel PPG<->BCG coherence (anti-spoof liveness).** `liveness/cross_channel.py`:
  the pulse must appear at the SAME rate in the PPG and the accelerometer ballistocardiogram
  (dominant-rate agreement within tolerance), plus optional living-band vitals (SpO2 90-100,
  skin temp 28-37C). A replay that fakes PPG but not a rate-aligned BCG fails; absent
  channels degrade gracefully. Honest boundary: necessary not sufficient; measures, never keys.
- **Gap closed — coupled session-key path** (`derive_session_key_coupled`) now tested:
  deterministic, binds every input, off-device rooting needs the live beacon, distinct from
  the decoupled construction.
- **Gap closed — epoch-cap runtime guard** (`session/epoch_guard.py`, `EpochCapGuard`):
  enforces `EPOCH_LENGTH_CAP_S` — a stalled beacon makes the epoch stale and `check()` raises
  `EpochStalled` to force a re-key (fail-closed; an un-bootstrapped guard is expired).

## Value vs timing in the key (revisited, decision STANDS)

- **Question raised:** should timing/numbers go INTO the key (the "coupled" §A embodiment)?
- **Decision (unchanged):** NO. value = QRNG (clean); timing/liveness TIMES the QRNG firing
  and GATES operations, but NEVER enters a value/KDF. Reasons: (1) biology/timing is
  low-entropy + estimable, so mixing it in shrinks the keyspace; (2) if biology is in the
  key, measuring your biology helps derive it — gating leaks nothing; (3) the presence
  BINDING coupling would add is already provided cleanly by gating the LK/epoch_key unwrap.
  Timing's benefit (unpredictable firing moment) is already captured by firing fresh QRNG
  at that moment.
- `derive_session_key_coupled` is REFERENCE-ONLY (labeled in-code, not a live path); the
  live derivation is `derive_session_key_decoupled`.
