# Atlas — Applications

What the Atlas capabilities (see [`CAPABILITIES.md`](CAPABILITIES.md)) unlock. Each application
names the specific capabilities that enable it. Two things make Atlas broadly applicable:

1. **Proof that a real, live human is present** — without a name, a face, or a stored biometric.
2. **Cryptography bound to that presence** — keys that exist only while the person is there, on
   any device that proves itself worthy, under no central authority, post-quantum-ready.

Applications are grouped by how directly the *built* core supports them. **●** = the enabling
capabilities are built and tested today · **◐** = partially built · **○** = designed / ecosystem-scale.

---

## The problem Atlas is timed for: the internet can no longer tell who's human

Bots, AI agents, deepfakes, synthetic identities, credential stuffing, account takeover, and
farmed "engagement" all exploit one gap: **the network can't prove a live human is on the other
end.** Atlas closes that gap at the cryptographic layer — and does it *without* building a
face/biometric database, which is the usual (privacy-destroying) way people try.

---

## 1. Human-or-bot, at the protocol layer ●

- **Proof of living human to any service** — prove you're a live person (not a bot, model, script, or replay) without revealing identity. *Enabled by:* PoLE liveness gate, cross-channel coherence, cross-device same-body binding, fail-closed anti-spoof gate.
- **Anti-Sybil / anti-farm** — one real human = one identity, enforced by living entropy that bot farms can't manufacture. *Enabled by:* hash-based personhood + per-context nullifier, Sybil cost model, motion re-ID farm-collapse.
- **Bot-free human spaces** — forums, knowledge bases, comment sections, and social layers that are architecturally human-only. *Enabled by:* per-epoch pseudonyms + PoLE gate + nullifier.

## 2. Passwordless, phishing-proof, verified-human login ●

- **Verified-human authenticator for banks & services** — authenticate a *person* to a relying party over the passkey/WebAuthn rails they already speak, binding live presence + step-up to the challenge. *Enabled by:* relying-party authenticator, RP-bound challenge, relay-resistant verify, WebAuthn format mapping.
- **Relay-/phishing-attack resistance** — the assertion is bound to the origin and action, so a relayed or replayed login fails. *Enabled by:* challenge/action/RP binding, single-use challenges.
- **Step-up for high-value actions** — a hardware-fingerprint step-up gates transfers and sensitive changes. *Enabled by:* YubiKey Bio high-stakes factor, intent gesture.

## 3. AI-agent era: humanity, provenance & anti-deepfake ●◐

- **"Made by a human" proof on content** — every capture/message can carry a proof it was produced by a live human on a real device, which a generation pipeline *cannot* forge (it lacks the live presence + device attestation + PoLE-derived key). *Enabled by:* accountable authorship provenance, live-provenance binding, capture-bound attestation.
- **Anti-deepfake camera** — photos/video signed at capture with depth-based presentation-attack detection, so a screen/replay is rejected and authorship is provable. *Enabled by:* media-vault capture pipeline, LiDAR PAD, provenance ledger.
- **Human-gated AI access** — require a verified live human (not an autonomous agent) to invoke high-impact actions; agents can't mint the presence proof. *Enabled by:* PoLE gate + authenticator.

## 4. Content authenticity, creative rights & anti-plagiarism ◐○

- **Automatic authorship timestamping** — every work timestamped to a tamper-proof record at creation, no filing or intermediary. *Enabled by:* provenance receipt, append-only ledger, beacon anchoring.
- **Plagiarism becomes cryptographically falsifiable** — duplicate content resolves to the earliest anchored entry. *Enabled by:* content-hash ledger + timestamp.
- **On-chain licensing & royalties** — attach terms to a work; royalties route to the creator with on-ledger usage tracking. *Enabled by (○):* licensing/royalty smart contracts, data marketplace.

## 5. Personal data sovereignty & living vaults ●

- **Vault only you (alive) can open** — files encrypted under keys that require your live presence; stolen hardware alone yields nothing. *Enabled by:* presence-gated secure vault, PoLE-conditioned key release, brick-at-rest.
- **Self-custody with survivable recovery** — you hold your keys, but a threshold of your own factors can rebuild them; no operator can. *Enabled by:* stratified recovery, total-loss anchor, re-rooting (operator-forbidden).
- **Zero-knowledge personal cloud** — storage/relay providers see only ciphertext, never keys or plaintext. *Enabled by:* blind relay, at-rest AEAD vault, non-custodial split storage.

## 6. Secure, human-verified communication ●◐

- **Forward-secret messaging** — Signal-grade dual-ratchet with accountable *or* deniable modes. *Enabled by:* conversation state machine, forward-secret chain.
- **Verified-human-only viewing** — content that only opens for a live, attested human (not a scraper or an archived copy). *Enabled by:* tunnel Mode-2 view-time gate.
- **Group sessions bound to live presence** — N people co-derive one live key, with a safety number to rule out a man-in-the-middle. *Enabled by (◐):* group live-LK relay, identity-bound KEM + safety number *(ran on two iPhones)*.

## 7. Protection for people under threat ●◐

For journalists, dissidents, whistleblowers, and domestic-violence survivors — where *coercion*, not just theft, is the threat:
- **Duress that looks like compliance** — a panic passcode / canary finger unlocks a decoy while silently alerting and locking the real vault. *Enabled by:* panic vault, behavioural duress channel.
- **Coercion-aware forensics** — evidence sealed and pushed off-device *before* it can be seized; access requested under distress is refused. *Enabled by:* escape-first forensic capture, forensic decision ledger.
- **Whistleblower provenance** — timestamp and prove evidence existed at time T, un-seizably. *Enabled by (○):* blockchain-anchored provenance, multi-jurisdiction splitting.

## 8. Presence-bound payments ◐

- **Arm-per-use card** — inert at rest; each transaction needs a live human + a physical intent press to arm a one-shot, scope-limited authorization. *Enabled by:* enclave arming authority, air-gapped card signer, nullifier registry, NFC arm-per-use session.
- **Fraud-resistant by construction** — a stolen card is dead without live presence; no reusable token to skim. *Enabled by:* single-use arming, double-spend nullifier.
- **Overlay, not replacement** — sits beside existing card/bank/CBDC rails. *Enabled by (○):* tap-to-pay, off-ramp, CBDC overlay.

## 9. Decentralized / self-sovereign identity ●◐

- **Contextual identity with no central issuer** — one anonymous root → unlinkable per-context pseudonyms; prove attributes (age, credential, membership) without revealing who you are or which other contexts you're in. *Enabled by:* identity tree, per-epoch pseudonyms + DP, anonymous credential, selective disclosure.
- **Interoperable with DID/VC ecosystems** — the credential seam and pseudonym model fit standards work (e.g. DIF), while the presence layer is the differentiator. *Enabled by:* crypto-agility credential seam.
- **Sybil-resistant one-person-one-identity** *without* knowing who the person is. *Enabled by:* personhood + nullifier.

## 10. KYC / compliance without surveillance ●○

- **Prove-the-requirement, not the person** — prove "over 18", "licensed professional", "resident of jurisdiction X", "one account per human" as a ZK attribute, audited on *process* not identity. *Enabled by:* attribute proofs, level-gated verification, jurisdiction-aware roles (○).
- **Regulated-context identity windows** — reveal full identity only for a specific purpose, time-boxed, then it closes and can't be correlated. *Enabled by (○):* time-bound role-scoped identity windows.

## 11. Healthcare ○◐

- **Patient identity + presence at point of care** — bind a record or an action to *this live patient now*, without a biometric database. *Enabled by:* PoLE gate, presence-gated records, role-scoped identity.
- **Consented, revocable data sharing** — release health data under a time-bound, purpose-defined proof-of-consent with an auditable receipt. *Enabled by (○):* proof-of-consent, compute-to-data, data marketplace.
- **Eldercare / dependent safety** — home-node guardian detects falls/distress and coordinates help while raw signals stay local. *Enabled by (○):* home-node AI guardian, guardian quorum.

## 12. Government & civic ○

- **Benefits/UBI without income surveillance** — allocate to a verified living person by jurisdiction, no means-testing bureaucracy. *Enabled by:* PoID region-scoped personhood, non-conditional UBI.
- **Coercion-resistant, one-person-one-vote elections** — liveness-gated, privacy-preserving tally, delegable/revocable roles. *Enabled by:* personhood + pseudonyms + role delegation, bicameral/quadratic governance.
- **Credentials without a central database** — licences, passports, permits proven locally as ZK tokens; no raw documents leave the device.

## 13. Enterprise & workforce security ●◐

- **Zero-trust device + workforce identity** — every device continuously proves integrity + live-human presence; a compromised or unattended device loses capability automatically. *Enabled by:* device attestation, presence gating, time-perishable trust, removal-state machine.
- **Insider-threat & coercion controls** — high-value actions need live presence + intent + optional multi-party approval; duress is detectable. *Enabled by:* arming authority, forensic ledger, duress channel.
- **Work/personal isolation** — cryptographically separate profiles; the employer manages/wipes only Work. *Enabled by (○):* profile separation, remote wipe.

## 14. Machines, robotics, vehicles & IoT ○

- **Human-presence-gated operation** — a machine/vehicle/robot runs only under verified living presence and halts safely on presence loss, with a legal-grade presence-logged audit trail. *Enabled by:* PoLE gate, signed attestation, provenance ledger.

## 15. Post-quantum migration substrate ●

- **Drop-in PQ posture** — hybrid ML-KEM + X25519 KEM and ML-DSA + Ed25519 signatures throughout, with a crypto-agility seam so schemes swap as standards evolve. *Enabled by:* hybrid KEM/sign, credential-scheme seam, PQC tunnel.
- **Harvest-now-decrypt-later defense** — even classical-only sub-parts (the anonymous credential) ride inside a PQ tunnel. *Enabled by:* PQC tunnel for presentations.

## 16. Randomness / entropy as a public utility ●○

- **Verifiable public randomness** — any service can consume beacon-anchored randomness (drand today; a living-entropy-sourced supra-jurisdictional beacon in the design). *Enabled by:* beacon protocol + drand client (●), three-tier beacon network + EaaS (○).

## 17. Privacy-preserving data economy ○

- **Sell proofs, not data** — monetize verified attributes/aggregates via zero-knowledge, time-limited, purpose-bound contracts with direct payment. *Enabled by:* data marketplace, compute-to-data, SMPC tag aggregation, proof-of-consent.

---

## Where this goes first (the honest near-term)

The **built and tested** core most directly supports, today: **proof-of-living-human, verified-human
authentication, content authenticity/anti-deepfake, presence-bound vaults & messaging, coercion-
resistant tooling, and post-quantum identity** — the applications marked ●. The finance, healthcare,
government, machine, and data-economy applications (◐/○) build on the same primitives but need the
device/hardware and ecosystem layers that are designed and disclosed, not yet shipped.

The through-line for all of them: **standard cryptography in, a living-presence trust substrate out —
so software can finally act on "a real human is here," privately, and without a central authority.**
