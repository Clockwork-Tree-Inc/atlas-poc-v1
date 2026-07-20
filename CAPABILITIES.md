# Atlas — Capabilities

Every capability of the Atlas system, grouped by layer. Atlas is a **novel machine and method
that turns standard, battle-tested classical and post-quantum cryptographic primitives into a
living, presence-bound trust substrate** — keys that exist only while a live human is present,
identity without biometrics, and no central authority.

This catalog is **exhaustive on purpose** and **honest about maturity**. Each item is tagged:

| Tag | Meaning |
|---|---|
| ✅ | **Built + tested** — implemented and covered by the CI test suite (376 Python + 110 Swift tests) |
| 🔨 | **Built** — implemented and exercised, no dedicated unit test |
| 🧪 | **Simulation / model** — a faithful reference model or adversarial simulation, not the production path |
| 📱 | **Device-gated** — runs on a physical iPhone + peripheral (ring / NFC card / Secure Enclave / camera / LiDAR) |
| 📐 | **Designed** — specified in the invention disclosure, not yet implemented |
| 🔭 | **Vision** — directional / ecosystem-scale; framing rather than a shipped mechanism |

> The cryptographic *primitives* are standard (NIST PQC + vetted classical). The **novelty is the
> machine, the method, and the system** that assembles them around continuous living presence —
> professionally confirmed novel (no single prior-art reference anticipates the integrated system).

---

## 1. Cryptographic primitives (the standard parts it consumes)

- ✅ **Hybrid KEM — ML-KEM-768 + X25519** (X-Wing-style combiner; transcript-bound HKDF)
- ✅ **Hybrid signatures — ML-DSA-65 + Ed25519** (dual-verify: accept only if both verify)
- ✅ **SLH-DSA / SPHINCS+** (SHAKE-128f) for the long-lived identity root *(Python; Swift is a seam)*
- ✅ **AES-256-GCM** AEAD with per-message random nonce + AAD binding
- ✅ **HKDF-SHA256** + a **length-prefixed combiner** (so `a‖b` can't collide)
- ✅ **SHA-256 / SHA3-256** protocol hash (SHA3 hand-rolled byte-identical across Python/Swift)
- ✅ **Shamir secret sharing over GF(256)** (2-of-3 and general m-of-n, malformed-share rejection)
- ✅ **CSPRNG** over the OS entropy source
- ✅ **Presence-fired Server-QRNG (Living Key)** — a clean QRNG value; arrival timing only jitters *when* it fires, never the value

## 2. Proof of Living Entropy (PoLE) — the pre-computational trust primitive

- ✅ **Bayesian liveness gate** — Beta-prior posterior `P(alive | signals)`, operate only at `p ≥ π*`
- ✅ **PoLE value = physiologically-*timed* QRNG** — the living signal schedules *when* a clean QRNG value fires; physiology never contributes key bytes
- ✅ **GBSS structured-entropy vector** — per-channel Shannon + Lempel-Ziv + spectral density across heart/skin/motion channels feeding the liveness likelihood
- ✅ **Entropy operators** — Shannon, min-entropy, Lempel-Ziv (LZ76), spectral entropy (pure-Python DFT)
- ✅ **Cross-channel pulse coherence** — the heartbeat must agree across PPG rate, HRV, and the accelerometer ballistocardiogram; SpO2 + skin-temp living-band gates
- ✅ **Cross-device same-body binding** — lag-tolerant Pearson correlation of phone-IMU vs ring-IMU (defeats ring-on-A / phone-on-B and on-table spoofs)
- ✅ **Handshake-bind verifier** — a random-N tap challenge co-seen by phone IMU + ring IMU + mic, bound to the Face-ID instant (fresh, co-located, fail-closed)
- ✅ **Perishable liveness** — a liveness break fails the *next* key derivation by construction (no separable "if present" check to bypass)
- ✅ **Biometric-template-free** — statistical/entropic comparison only; **no biometric template stored, no identification** (*liveness ≠ identity*)
- 🔨 **Ring biology source** — real R10 PPG oscillation-vs-flatline presence verdict
- 📐 **Continuous Capillary Attestation (CCA)** — ultrasonic sub-surface capillary read for simultaneous liveness + finger-specific anchor
- 📐 **Dual-assurance PoLE production gate** — both a liveness-entropy check and a behaviour check must confirm "alive" before any PoLE value is produced
- 📐 **Upward-collapse property** — one biological signal serves the crypto session, the economy, and network intelligence at once

## 3. QRNG-anchored device-integrity attestation

- ✅ **Ratchet-paced signed liveness attestation** — hybrid ML-DSA + Ed25519 over injective length-prefixed (beacon, digest, operate-flag, challenge)
- 🔨 **App Attest / DeviceCheck gate** 📱 — real Apple attestation (flag-stubbed under free provisioning)
- 📐 **Dual trust-channel architecture** — PoLE flows *up* (body → devices → network); QRNG-fresh attestation flows *down* (node → wallet → ring); SECURE_MODE needs both healthy at once
- 📐 **QRNG/PoLE division of labour** — QRNG entropy for long-lived keys; PoLE entropy for short-lived session keys
- 📐 **Firmware / boot-chain / OS measured attestation** under a secure-element key with fast-expiring non-replayable challenges

## 4. Key architecture & the Living Key Ratchet

- ✅ **RAM-only session keys** with explicit zeroize (reuse-after-destroy raises)
- ✅ **Decoupled session-key derivation** — `HKDF(LK, epoch_key, PoLE_value, prev_key, ctx)` (timing never enters the value)
- ✅ **Forward-secret ratchet** — `K[t+1] = HKDF(K[t] ‖ H(entropy) ‖ beacon ‖ drand_round)`, one-way
- ✅ **Biologically-jittered ratchet cadence** — a live sensor byte maps to the step interval (the *when* only)
- ✅ **Purpose-scoped context keys** — storage / recognition / tunnel label separation
- ✅ **Secure-enclave model** — non-extractable master key, device-bound AAD-gated seal/release, robust biometric match
- ✅ **Split-TSK identity** — user-half (Atlas Card) + blind server-HSM half; both required to reassemble; server half non-exportable
- ✅ **Identity tree** — SPHINCS+ root → System-ID → fixed children (real-id / anonymous / authorship / recovery) with rotation generations
- 📐 **Four-level hierarchy** — Hardware Enrollment Key (dead-end) → Device Key (QRNG) → True-Self Key (2-of-3 threshold) → Session Key (RAM-only)

## 5. Presence gating & the living session

- ✅ **Presence-conditioned epoch-key unwrap** — the epoch key is delivered *wrapped*; unwrap requires the enclave to release the enrollment secret under live presence → no presence, no key, *mathematically*
- ✅ **Presence-resume lifecycle** — HKDF resumption-code chain proving same-ring across a disconnect; PRESENT / SUSPENDED / LOCKED machine with grace window + forensic lock events
- ✅ **Recognition + evolving tunnel** — per-epoch X25519 ephemeral bound to the session key; leaderless symmetric DH; per-epoch tunnel re-key
- ✅ **Hybrid PQ recognition** — ML-KEM-768 + X25519 two-encapsulation handshake (harvest-now-decrypt-later resistant)
- ✅ **Epoch-cap runtime guard** — fail-closed re-key when the beacon stalls or overruns the cap
- ✅ **Swappable live-signal source** — one `SignalSource` seam behind ambient (phone sensors) or ring biology; source-agnostic timed ratchet
- ✅ **Full device value/timing chain** — challenge-response device auth, presence-gated epoch advance, RAM-key-wipe containment, independent continuity ratchet, forward-secret message ratchet
- 🔨📱 **On-device full-stack runtime** — Secure-Enclave storage + ambient PoLE + epoch LK wrap/unwrap + presence-gated advance + duress, running on a physical iPhone
- 📐 **Time-perishable trust / Trust Continuity Index** — a continuously-recalculated per-entity score driving a *continuous* permission gradient, not a binary gate

## 6. Multi-device trust, sentinel & ring hardware

- 🔨📱 **R10 ring BLE client** — real CoreBluetooth GATT, Nordic-UART, real-time HR stream, encrypt-on-receipt under the Device Key
- 🔨📱 **Ring diagnostics + live pulse verdict** — full GATT enumeration, PPG oscillation presence gate, rate/accel telemetry, tap-onset extraction
- 🔨📱 **Swappable-wearable seam** — a `Wearable` capability protocol (pulse / on-body-motion / high-rate-IMU / secure-element); features light up from what a device *proves*, so any wearable plugs in
- 📐 **Sentinel-centered trust** — a hardened wallet holds the root hierarchy, authenticates every device, mediates high-value ops; interface devices hold no keys and are assumed compromised
- 📐 **Trust Triangle** — ring + human + wallet all simultaneously active for any high-value op
- 📐 **Phone as ditchable surface** — phone is UX + PoLE aggregator, not the trust root; loss contained by attestation failure + RAM-only keys
- 📐 **Dumb mode** — drop to telephony + SOS only on attestation mismatch
- 📐 **Atlas ring / sentinel / dock / node hardware** — purpose-built rings (PPG/GSR/IMU/secure-element/UWB/NFC), sentinel wallet, charging dock, home & event nodes

## 7. Enrollment, wear & removal

- 🔨📱 **Multi-factor enrollment ceremony** — liveness + Face ID + enrol-scope password + physical double-click → identity tree + enrollment secret
- 🔨📱 **Co-motion ring-lock** — QRNG N-tap challenge correlating phone taps with ring accelerometer, binding ring↔phone↔one body at enrollment
- ✅ **Removal-state machine + containment** — ACTIVE / VOLUNTARY / SUSPICIOUS; RAM-key wipe on suspicious removal; reconnect trajectory-coherence check
- 📐 **Dock enrollment ritual** — finger + ring + sentinel co-presence; obfuscated fingerprint stays local; separate Ring-A / Ring-B binding
- 📐 **Authorized vs unauthorized removal** — dock + finger + removal-mode for authorized; contact-loss + anomalous motion + missing dock event → escalation
- 📐 **Ring rotation swap** with no PoLE gap; dual-ring-loss fallback mode

## 8. Anti-coercion & duress

- ✅ **Panic vault (duress slice)** — dual-passcode decoy, surface-identical to the real vault, real key bricked on suspicion, decoy pre-seeded
- ✅ **Behavioural duress channel** — salted-hash normal/duress patterns + "canary finger"; observationally identical auth with an internal coercion flag; constant-time compare
- ✅ **Append-only forensic decision ledger** — signed, vault-sealed, hash-chained events + risk engine (ROUTINE / SUSPICIOUS / DURESS / EMERGENCY), pseudonymous subject handle
- ✅ **Escape-first forensic capture** — seals + emits the first burst off-device before the sustain loop; no local plaintext buffer; beacon-anchored tamper-evident chunks
- 🔨📱 **Duress UI** — real and panic paths visually indistinguishable
- 📐 **Silent panic password + silent capability degradation** — appears normal while rate-limiting transfers, alerting guardians, and enriching telemetry
- 📐 **Distress detection** — HRV spikes / GSR elevation / struggle motion / pupil / voiceprint arousal shift state invisibly
- 📐 **Three independent silent duress channels** — canary finger, duress tap pattern, deliberate Face-ID failure
- 📐 **Distress-choke on forensic access** — access requested under detected distress is refused (a coercer can't reach the records of the coercion)

## 9. Vaults, storage & provenance

- ✅ **At-rest AES-256-GCM vault** — ciphertext-only store, per-entry AAD, PQC key-wrap only at the wrap moment, "brick" view at rest
- ✅ **Presence-gated secure vault** — storage key sealed in the enclave, released only on live presence; per-item provenance stamp; phone-only vs non-custodial (KEM-wrapped) backup
- ✅ **Media-vault capture pipeline** — one presence-gated step: provenance-sign → publish epoch witness → seal into the vault; camera PAD (LiDAR depth + moiré); ledger anchoring; re-verify-on-open
- ✅ **Accountable authorship provenance** — signs the earliest frame with a liveness-gated authorship pseudonym; capture-bound attestation (anti-transplant); "verified human behind this" proof
- ✅ **Live-provenance binding** — an epoch witness key obtainable *only* inside a live presence-gated session pins the "when"; public registry holds only the public halves
- ✅ **Append-only provenance ledger** — content-hash-only hash chain, membership + full-chain tamper-evident verify
- ✅ **PAD (presentation-attack detection)** — LiDAR depth-plane variance + moiré/periodicity, folded into the transcript (advisory)
- 🔨📱 **Direct-capture camera + LiDAR PAD** — AVCaptureSession HEVC capture with provenance signing and planar-screen rejection
- 🔨📱 **In-app voice capture** sealed to the vault; **vault file browser** with decrypt-on-demand under presence + QuickLook
- 📐 **Blockchain-anchored provenance** — hashes + minimal commitments for immutable proof-of-existence (art, research, evidence, whistleblowing)
- 📐 **Home-node black-box guardianship** — event-triggered forensic retention under multi-key threshold access
- 📐 **Multi-jurisdiction file splitting**, censorship-resistant publishing, remote wipe, hardware-enforced wipe-battery floor

## 10. Messaging & conversations

- ✅ **Two-party conversation state machine** — Signal-style dual chains, bounded skipped-key cache, replay/over-skip refusal, ACCOUNTABLE (signed) vs DENIABLE (AEAD-only), position-binding AAD, wire codec, restart-resume
- ✅ **Forward-secret directional chain** — one-way HKDF chain (delete-as-you-go), deterministic lockstep, direction-scoped seeding
- ✅ **Two-device co-derived Living Key (LK)** — HKDF-combines ≥2 fresh device contributions + drand round; leaderless; refuses <2
- ✅ **Tunnel two send modes** — normal AES-256-GCM, and a *verified-human view-time gate* (online beacon + fresh enclave attestation required to open)
- 🔨📱 **Group live session** — N users co-derive one shared group LK over per-pair KEM channels; identity-bound KEM keys + a safety number to detect MITM *(ran end-to-end on two iPhones)*
- 🔨📱 **Blind-relay 1:1 + group messaging clients** — forward-secret sealing over a node that holds no keys
- 📐 **Atlas-native mail, secure calling, publishing/forums, knowledge streams** with authorship provenance and PoLE bot-exclusion

## 11. Recovery, threshold custody & re-rooting

- ✅ **Stratified recovery** — Shamir 2-of-3 of the identity seed; the biometric share bound to the enclave (device-present); total-loss recovers from the two portable shares (card + context), no biometric; passcode PBKDF2
- ✅ **Multiple recovery paths** — card / in-person ceremony / total-loss / normal-auth; all holder-authority + attestation gated (**no operator path exists**)
- ✅ **Total-loss recovery anchor** — real-you unlinked from digital-you; a `(name, password)` scrypt selector (1:1, *no* 1:N biometric search); a four-factor AND-ed bridge (password ∧ biometric ∧ recovery-person signature ∧ threshold shares); recovery-person as a *liveness witness*
- ✅ **System-ID re-rooting + TSK rotation** — forward-healing re-root from a durable root (new generation unlinkable); **holder-authority-only** (operator forbidden by construction)
- ✅ **USB DualDrive recovery blob** — KEM-wrapped Shamir share, AES-GCM sealed, opaque if lost
- ✅ **Card-loss recovery** — user-half re-split Shamir n=5, k=3 across servers
- 🔨📱 **On-device distributed recovery arming + total-loss recovery** wired into the app
- 🧪 **Proactive secret re-sharing** — refresh committee shares *without* reconstructing the secret (Herzberg-style), plus a **verifiable (Feldman-VSS)** variant that detects and attributes a cheating dealer
- 📐 **Recovery Card, guardian-quorum recovery, estate/inactivity + secret-heir claim, death/revocation via multi-device consensus**

## 12. Identity, pseudonyms, anonymous credentials & personhood

- ✅ **Anonymous credential (BBS+ / Pointcheval-Sanders)** — one credential over [claim, level, system-id]; **unlinkable re-randomized presentations** revealing {claim, level} while hiding system-id; pure-Python PS backend gates CI (Ursa BBS+ optional)
- ✅ **Crypto-agility credential seam** — abstract issue/present/verify/disclose behind one interface, so a post-quantum anonymous credential drops in later with no tree change
- ✅ **PQC tunnel for credential presentations** — every classical BBS/PS proof rides inside an ML-KEM-768 + X25519 tunnel (harvest-now-decrypt-later safe)
- ✅ **Level-gated verification + accountability disclosure** — the level is taken from the cryptographically-revealed message (anti-escalation); only the *holder* can disclose the system-id (no involuntary opener by design)
- ✅ **Per-epoch pseudonyms + differential privacy** — `H(child_secret, drand_round)` unlinkable-across-epochs handle; Laplace-noise counter bounds cross-epoch correlation
- ✅ **Opaque handles + pseudonym tiers** — PUBLIC / PRIVATE / ANONYMOUS per-label unlinkable pseudonyms
- ✅ **Assurance levels + auth modes** — L0/L1/L2; bind-to-external-identity vs Atlas-as-identity (consented, logged)
- ✅ **Non-custodial storage** — on-device HKDF key or Shamir 2-of-3 split (device + user + cloud); server holds only status + ≤1 share
- 🧪 **Post-quantum hash-based personhood** — SHA3 commitment + per-context **nullifier** (Sybil-detectable yet cross-context unlinkable) + domain-separated Merkle membership; models a STARK/FRI proof
- 📐 **Time-bound role-scoped identity windows** — identity as a temporary cryptographic event bound to one time/purpose/jurisdiction/institution; non-reusable, non-correlatable, leaves no persistent identifier
- 📐 **Selective disclosure modes, role isolation, attribute proofs, jurisdiction-aware roles, delegation/revocation, per-space mask model**

## 13. Verified-human authenticator (relying-party / passkey)

- ✅ **Relying-party authenticator** — authenticates a *person* to a bank/service; RP-bound challenge (WebAuthn-style origin binding); fail-closed without live presence; step-up requires a hardware fingerprint
- ✅ **Relay-resistant assertion verify** — enforces challenge/action/RP match, handle↔public, liveness, authorship signature, registered step-up key
- ✅ **Mock relying-party server + WebAuthn passkey format mapping**
- 🔨 **End-to-end auth demo** — in-process bank: login, step-up transfer, relay-attack rejection, no-presence fail-closed
- 🔨📱 **On-device RP client** (mock bank over the network)

## 14. Payments (arm-per-use, two-factor)

- ✅ **Transaction descriptor + well-formedness gate** — frozen {amount, recipient, nonce, timestamp, epoch}, canonical JSON
- ✅ **Enclave arming authority** — mints a one-shot arming only with a *current* liveness attestation AND a physical intent press (optional ring co-motion); binds descriptor + card + nonce
- ✅ **Air-gapped payment card signer** — on-card Ed25519 no-export, mutual-freshness challenge, exactly-one-signature enforcement
- ✅ **Nullifier registry** — spent-nonce single-use, double-spend rejection
- ✅ **YubiKey Bio payment intent** — fingerprint-on-key signature over the exact transaction (separate-device isolation, fail-closed)
- 🔨📱 **Enclave arming minter + NFC arm-per-use card session** — real CoreNFC ISO-14443 AID + challenge/arm APDU contract (the sign step is deliberately deferred, fail-closed — no faked payment)
- 📐 **Atlas Card global tap-to-pay, single-use virtual numbers, spend controls, stablecoin/fiat off-ramp, CBDC overlay, human-presence machine gating**

## 15. Networking, blind relay & node mesh

- ✅ **Blind relay node** — store-and-forward of opaque sealed blobs; the node holds no keys and sees only envelope metadata
- ✅ **Public verifier / anchor node** — publish + verify provenance, RP register/challenge/verify, serve per-epoch witness publics (never the LK)
- ✅ **PQC tunnel server** — Mac-side hybrid ML-KEM-768 + X25519 → AES-256-GCM messaging + ACK
- ✅ **Cross-language wire codecs** — provenance bundles + conversation envelopes rebuildable byte-for-byte in Swift
- ✅ **Two-phone end-to-end demo** — Phone A/B through a blind relay: KEM establish, sealed message, provenanced-photo verify against the public witness (node stays blind)
- 🔨 **Node HTTP dispatch + live LAN dashboard**
- 📐 **Five-layer node mesh, autonomous privacy zones, institution-as-node, regional clusters, cross-node fault detection, sealed multi-stream compartments**

## 16. Anti-spoof / adversarial defense

- ✅ **Fail-closed liveness gate** — min-entropy + Lempel-Ziv + autocorrelation + total-variation checks reject flat/looped/synthetic streams
- 🧪 **Sybil / farm-resistance cost model** — cost-per-valid-identity across replay / synthetic / real-human attackers
- 🧪 **Motion soft-biometric re-ID + farm collapse** — per-identity signature (~8× over chance); duplicate-radius and gait-reuse collapse farms
- 🧪 **Mixnet anonymity model** — padding + batching + H-hop onion cascade + cover traffic vs an observer's sender-identification and activity-detection attacks
- 📐 **Continuous entropy-authenticity signature, dual-stream contradiction detection, entropy-health gradient, anti-replay/emulation envelope, PUF hardware-mimicry defense, distributed verdict oracles, physical mesh tamper circuits**

## 17. Beacon network & Entropy-as-a-Service

- ✅ **Beacon protocol + real drand client** — League-of-Entropy quicknet, `randomness == SHA-256(signature)` integrity **and BLS threshold-signature verification** against the pinned group public key (validated against a live round; known-answer test)
- ✅ **Offline deterministic beacon** — drand-shaped reproducible rounds for sealed CI
- ✅ **Presence-fired Server-QRNG** — clean QRNG Living-Key value; arrival timing only jitters the next sample
- 📐 **Public randomness utility, three-tier contributor model, P2P Sybil-resistance-by-living-entropy, VDF commit-reveal aggregation, geographic cryptographic equity, beacon service tiers**

## 18. Space tier — supra-jurisdictional root of trust

- 📐 **LEO constellation root of trust** — a threshold set of hardened satellites (each with a QRNG + radiation-tolerant HSM/TEE + measured boot); **holds no personal data**, only public cryptographic artifacts. The constellation size scales to the threshold policy; the **roles are fixed regardless of the number** — Trust Anchors (hold the root key shares, sign checkpoints/policy/randomness) and Relay/Beacon nodes (high-availability broadcast/uplink)
- 📐 **Threshold root key ceremony** (t-of-n per-satellite shares), signed global epoch markers, ledger checkpoints/non-equivocation, multi-party firmware updates, constitutional anchoring, space-co-signed emergency access
- 🔭 **Supra-jurisdictional independence** — no single nation/corporation/data-center can unilaterally subvert the root

## 19. Economic layer — Proof of Entropy

- 📐 **PoLE ≠ PoE separation** — PoLE is a liveness gate that issues no rewards; every reward proof is void for an epoch without a PoLE attestation
- 📐 **Non-conditional UBI minted first**, cost-of-living-anchored (dignity, not subsistence); **variable rewards** as a decaying top-up; **harm-exclusion as architecture** (harmful behaviour fails the physiological safety gate)
- 📐 **Extensible proof classes** — Effort, Wellness, Attention, Engagement, Discipline, Altruism, Growth, Data-Integrity, Consent, Learning, Compute, Individual-Dignity (PoID)
- 📐 **Burns/buybacks, issuance split, mint-gate invariant (capital can never mint), impact routing, national/city wrapper denominations, internal cost-of-living oracle**
- 🔭 **13-pathway earning model, entropy taxonomy, "fund life by living" thesis**

## 20. Governance — constitutional invariants

- 📐 **Pre-constitutional invariants** (Life, Organic Response, No Harm, Tolerance) + 23+ constitutional invariants (PoLE primacy, mint-gate, key-hierarchy, panic-phrase sovereignty, browser prohibition, beacon public-good, stable-token, pre-computational trust layer…)
- 📐 **Amendment firewall, bicameral governance (Commons + Stewards), quadratic/conviction voting, People's Prayer System, guardian benches, governance smart-contract suite**

## 21. AI tiers & directed compute

- 📐 **Three-tier constitutional AI** — deterministic/generative separation invariant; Wallet AI (personal ML armour, yes/no verdicts, attacker-drift immune); Home-node "Butler"; Server "Government" (identity-blind); verified anonymous training pipeline; double harm filter
- 📐 **Browser prohibition + Atlas Secure Browser** (no JS engine on any wallet tier)
- 📐 **Directed Compute** — idle compute to a constitutionally-curated problem pool, PoLE-gated against bot farms
- 🔭 **Dual-scale / Gödelian / planetary living-systems intelligence, Verified Knowledge Library**

## 22. Platform, entities & OS

- 📐 **Three-entity model** — commercial PoLE licensing / non-profit trust foundation / charity-UBI fund
- 📐 **Conformance registry, app marketplace (governance-signed only), AtlasOS curated runtime, anti-abuse stack (attestation, root detection, distance-bounding, GPS anti-spoof)**
- 🔨 **Honesty flags** — the app declares at startup which components are REAL vs STAND-IN vs STUBBED vs SIMULATED

---

## Test & CI summary

- **CI runs on every push/PR** — Python backend (`pytest`, Python 3.12, pure-Python credential leg gates CI) + Swift core (`swift test`, macOS).
- **~486 automated tests in CI** — **376 Python** across 46 files (incl. dedicated `test_security_properties`, `test_threat_model`, `test_value_timing`, `test_coupled_epoch_gaps`) + **110 Swift** including byte-exact Python↔Swift **parity vectors**.
- **~35 adversarial simulation tests** (mixnet / pq_root / provisioning / reshare / shred / zk_personhood) run outside the CI gate.
- **Honest gaps, stated plainly:** Swift SPHINCS+ is a seam (Python ships real `pyspx`); Swift ML-KEM/ML-DSA carry "verify-against-SDK" caveats (confirm against the shipping CryptoKit + the Python reference); Swift has no BBS+/live-binding yet; NFC payment-signing and moiré PAD are deferred/stubbed.
  - **Layers:** the **Spaces** layer — social containers *within a vault* (personas, content, market, polls, votes, soul-bound participation tokens) — is **built + tested** on both platforms. The **economy** is built but **not included here** (patent track; its capabilities are described, not shipped). **Governance**, the **AI** tiers, and the **space *tier*** (satellites — ATLAS VI, a different thing from Spaces) are **designed, not built**.
  - **Crypto posture:** the core is **post-quantum** (ML-DSA-65 + Ed25519 signatures, SPHINCS+ root, ML-KEM-768 + X25519 KEM), and **persona↔persona unlinkability is hash/HKDF-derived ⇒ post-quantum**. The classical (not-yet-PQ) residue is narrow: the Pointcheval–Sanders anonymous credential's *same-credential multi-show* unlinkability (BLS12-381 pairings), the discrete-log range-proof *soundness*, and the drand BLS beacon — with a **STARK migration path** for the range proof and a post-quantum anonymous credential as the open research item.

The pattern throughout: **the built core is real, tested, and cross-language-verified; the broader ecosystem is designed and disclosed.** Nothing here claims more than the tag admits.
