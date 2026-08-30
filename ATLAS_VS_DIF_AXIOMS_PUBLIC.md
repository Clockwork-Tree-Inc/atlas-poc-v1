# ATLAS and the Ten Axioms for Digital Identity Design

**Reference:** Ben Taylor (CEO, LedgerDomain), *"Ten Axioms for Digital Identity Design,"* Decentralized Identity Foundation (DIF), Trusted AI Agents Working Group, 13 Aug 2026.

The Ten Axioms are a *mandate*: ten hard constraints Taylor argues every modern identity system must defend against — and that most of today's systems violate (all-powerful admin keys, phone-home OAuth, surrenderable seed phrases). We think they're a good bar. ATLAS wasn't built *from* the axioms, but it converges on them, and on the hardest one — coercion — it goes further.

For a *trust* primitive, credibility comes from surviving scrutiny. This is how ATLAS measures against each axiom.

---

## Scorecard at a glance

| # | Axiom | ATLAS |
|---|-------|-------|
| 1 | No single omnipotent key | **Structural** — two-tier split; the server side *mathematically* cannot reconstruct |
| 2 | Post-quantum; key rotation | **Strong** at every network layer; credential *unlinkability* still classical (no PQ standard exists) |
| 3 | Minimize the witness set | **Strong** — witness set is a device choice (device-agnostic) |
| 4 | No surrenderable secret | **Strong** — enclave keys + liveness, nothing to hand over |
| 5 | Uncoercible credential | **Where ATLAS goes furthest** |
| 6 | No security through obscurity | **Strong** — open by design; unlinkable personas |
| 7 | The phone-home test | **Strong** — verification is offline/by-signature |
| 8 | A DID below, a VC above | **Direct match** |
| 9 | Audit every agent's reach | **Strong** — capability-scoped agents + provenance ledger |
| 10 | Verify keys long after they die | **Strong** — append-only history, offline verification |

---

## Axiom by axiom

**1 — No single omnipotent key.** The root is split **structurally, not by policy**: the seed is the XOR of a your-side half and a server-side half, and each half is separately Shamir-split — t-of-n across holders you control, k-of-m across the server side. Reconstruction requires a threshold of **both**. The server side only ever holds shares of its own half, an independent random value acting as a one-time pad against the seed, so *every server operator colluding, presenting every share they hold, reconstructs nothing.* That is not a rule the code checks and might forget to enforce; it is a property of the arithmetic. Symmetrically, a stolen phone and token cannot recover the seed without the server quorum, and each side remains fault-tolerant to losing holders.

**2 — Post-quantum, and rotation.** Post-quantum at every network-facing layer: ML-KEM-768 + X25519 (X-Wing hybrid) for key exchange, ML-DSA-65 and SPHINCS+ for signatures, AES-256 for content, with continuous ratchet rotation and fresh randomness per step. That answers "harvest-now, decrypt-later" for transport.

We are precise about the one place it does not yet reach. Anonymous-credential **authenticity** is post-quantum — an ML-DSA signature over the non-anonymous parts. Credential **unlinkability** still rests on classical pairing cryptography, because **no standardised post-quantum anonymous-credential scheme exists yet, for anyone.** The scheme sits behind a swap interface, with a test proving it can be replaced without changing a line of calling code, and our hash-based (therefore quantum-resistant) replacement is already modelled and costed. Until a standard lands, a break there would correlate past pseudonyms under a *blind* root — never to a legal identity — and re-rooting heals it forward.

**3 — Minimize the witness set.** Keys are born in the device secure element; the user holds genesis; no raw biometric is ever transmitted (only proof objects); there is no seed phrase to photograph or overhear. Because ATLAS is **device-agnostic** (the secure element is an abstraction), the witness set is a *deployment choice*: the intended trust-tier device strips the heaviest witnesses while keeping a dedicated secure element, re-lockable verified boot, and non-proprietary hardware attestation, and a dumb hardware token is the even-lower-witness option. Crown-jewel material lives on the threshold holders, never a single phone.

**4 — No surrenderable secret.** No memorized secret and no recovery phrase — identity is secure-element-held keys plus liveness. Like a passkey, there is nothing to hand over under pressure.

**5 — The uncoercible credential (where ATLAS goes furthest).** The standard prescription is m-of-n across separated parties plus time-locked veto and duress decoys. ATLAS combines those **and adds a duress signal**: the system can recognize that a present human is under coercion and fail a high-value operation *closed* — without tipping off the coercer. Surrender-resistance + coercion-resistance + duress-detection, together.

**6 — No security through obscurity (Kerckhoffs).** Open by design (a system must be secure even when everything but the key is public). **Unlinkable personas** defeat the cross-context correlation that powers modern deanonymization, and value in the system is *earned and internal* — not a public wealth signal — so ATLAS doesn't hand attackers the "who holds value, and where do they live" target that drives coercion attacks.

**7 — The phone-home test.** ATLAS passes it: the personhood check is no-network/no-server, and proofs verify by signature, not by calling an issuer. Any server-assisted liveness check stays non-identifying and never crosses into the identity-verification path — identity verifies offline.

**8 — A DID below, a human-meaningful credential above.** A decentralized machine identifier (exposed as a W3C DID, `did:atlas`) plus optional, per-persona human-meaningful verifiable credentials — verified by signature, no phone-home.

**9 — Audit every agent's reach.** Capability-scoped AI agents + a cryptographic provenance trail + an append-only ledger give exactly the "verifiable record of what each agent can reach, has reached, and sent" the axiom demands. Every agent action borrows a **verified human's** authority — scoped, revocable, and logged.

**10 — Verify keys long after they die.** A provenance ledger + a verifiable public randomness beacon + chained history make proof objects self-contained, so a signature verifies offline long after its algorithm is superseded.

---

## Where ATLAS goes furthest

Axiom 5 (coercion) is the hardest, and it's where ATLAS adds a layer the essay doesn't: **duress sensing.** m-of-n plus time-locks make single-person coercion structurally insufficient; a duress signal adds recognition that a present human is under coercion, so a high-value operation can fail closed *without tipping off the coercer.* Surrender-resistance, coercion-resistance, and duress-detection, together.

## In short

Measured against the systems the axioms are scolding, ATLAS is ahead on most of the ten — by design intent, and increasingly in shipped code — and it goes furthest on the embodiment/coercion axiom.
