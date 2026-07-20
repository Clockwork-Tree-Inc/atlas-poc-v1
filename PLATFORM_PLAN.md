# Atlas Platform Plan — Social Layer, Economy, Security & Build Sequence

> Canonical plan capturing the design converged on across the identity/social-layer work.
> One source of truth for both build tracks. Marks **built** vs **new** vs **downstream** honestly.

---

## 0. Thesis (the spine over everything)

**One substrate — verified human + provenanced message + vault-hosted space + permissioned
cross-boundary invitation — exposed as many shapes. Not separate apps.**

The claim is **not** "bad things can't happen." It is: **the truth is provable.** Atlas does not
promise a world without lies, deepfakes, theft, or fraud — it makes the real distinguishable from
the fake (a human can prove they're real, an author can prove authorship, a buyer can prove they
bought, a rights-holder can prove terms). *Harm isn't prevented; truth is recoverable.* This framing
survives a skeptic where "can't be faked" never would.

**Governing principle — THE USER CHOOSES.** Non-custody made concrete: Atlas allocates no quotas,
hosts nothing on its terms, sizes nothing. The user decides — on hardware they own. No platform-set
default may be un-overridable.

---

## 1. Identity model (the outermost layer)

```
System-ID VAULT        ← outermost; non-custody, on YOUR device
  • blind System-ID (reassembled card + server-HSM half; never surfaced)
  • the root container everything derives from
  └─ CHILD PSEUDONYMS = PERSONAS   (tree.profile(username, tier))   ✅ built (Phase 1)
       ├─ "aunali"    → certifiable REAL you (real-id verified)
       ├─ "horseshit" → pseudonym, unlinkable
       └─ "journalist"→ pseudonym holding org credentials
             └─ each persona owns its own slice: vault · messaging · spaces · feed · credentials
```

- **Persona** = a `(username, password)` account, **blindly stored** server-side, whose crypto
  identity is a System-ID child that never surfaces. Distinct `(username, tier)` → distinct,
  mutually **unlinkable** persona. Generalizes the recovery-anchor `(name,password)→blind selector`
  to everyday login. **Built:** `atlas/persona/` + `IdentityTree.profile()` + 9 tests.
- **One System-ID → many personas.** One may be **certified real** (`realid/verification`); the rest
  stay pseudonymous.
- **Accountable pseudonymity (LOCKED invariant):** pseudonymous by default; real-ID is **bound**
  (cryptographically, unique-human) only for accountable actions (economics/sales/contracts), and
  **disclosed** only under authorized cause (dispute/fraud/lawful) via selective disclosure. Real-ID
  is a *gate on economic actions*, never a login requirement.
- **Handle resolution is disclosure-tier-aware, NOT one global token:**
  - anonymous / Commons space → per-space **nym** (`space_pseudonym`), unlinkable;
  - real-identity space (Direct/Family/Org) → the certified persona's **messaging slice** —
    **NOT** the root `systemIDHandle` (the cross-partition master id that verification + device
    enrolment key on), and **NOT** the raw real-id child (that's the legal-ID vault handle).
  - **Backwards-unlinkable:** a slice handle is `H(one-way(system-id, …))` — an observer can't invert
    it to the root or correlate it to other slices; only the System-ID holder can prove linkage
    (resolvable under authorized cause).
  - **FIX PENDING:** committed mailbox (`2576b75`) uses root `systemIDHandle()` → repoint to the
    persona/disclosure-tier slice.

---

## 2. Substrate — built vs new

| Capability | Primitive | Status |
|---|---|---|
| Personas / child pseudonyms | `atlas/persona/`, `IdentityTree.profile()` | ✅ built + tested |
| Blind login selector | `persona_selector` (scrypt + OPRF) | ✅ built |
| Verified human / real-ID | `realid/verification`, personhood gate, `PseudonymTier` | ✅ substrate |
| Selective-disclosure credentials | `realid/ps_credential` | ✅ substrate |
| Provenanced message/media/doc | `provenance/capture`, `live_binding` | ✅ substrate |
| Vault (user-sized, ciphertext-anywhere) | `recovery/threshold_seal`, `session/secure_vault` | ✅ substrate |
| Persistence: Private / Public | `ledger` `IndividualLedger` / `GlobalAnchor` (D2/B2 hardened) | ✅ substrate |
| Direct (1:1) messaging | co-derived A-B key + blind relay | ✅ built (2-phone demo) |
| Space (threshold root + presence vault + governance) | `spaces/space.py` | ⚙️ partial |
| Device/node attestation (SE-gated) | `attestation/device`, `AttestationVerifier` | ✅ substrate |
| Liveness / PoLE | `liveness/*` | ✅ substrate |

**Genuinely new (the sharp edges):**
1. **Cross-boundary permissioned invitation / accreditation-delegation authority** — permissions
   *compose and don't leak upward*; an admin can only invite across borders they can cross. This is
   also how orgs credential people (APA→doctor, press→journalist) and orgs credential orgs (Guild).
   *Where privilege-escalation lives — design + adversarially pressure-test before building.*
2. **Deterministic rights/consent gate** — upstream of models & commerce; decides, generative/provider
   obeys, never given the choice.
3. **Media-decode isolation** — the parser surface (see §7).

---

## 3. Social layer — Spaces (one primitive, many shapes)

**A Space is a permissioned view over vault storage** = `{ type, persistence-mode, persona members,
permission grants }`. Vault-hosted. Self = Direct-with-yourself; Commons = a Space with the walls
removed; Movement/Org = the same vault-hosted presence at two scales.

**Space types (LOCKED names):** Self · Direct · Family · Friends (Huddle = group chat within) ·
Movement (a seed that grows into site/newsletter/campaign; self-hosted from vault; free for close
circle, paid to expand) · Host (mixed admin-defined membership) · Org (workspace; LinkedIn-shaped,
vault-hosted; priced by nature not size — nonprofit/commons-adopter free, business pays; promotable
later to **Guild** = accreditation tier) · Commons (public, Reddit-shaped; identity optional).
*(Removed, do not reintroduce: Hearth, Guild-as-room, Journal/Conversation/Circle.)*

**Persistence modes (LOCKED, orthogonal — any space, any mode):**
Present (live only, no stored copy) → Fading (user-set TTL, then deleted) → Private (permanent,
ledgered between parties, provable by them) → Public (permanent, global-anchored, provable to anyone).
Escalation is least→most durable/witnessed. A Market review ("Vouch") is always Public.

**Mode → primitive:** Present = blind relay no-retention · Fading = relay/vault + TTL ·
Private = `IndividualLedger` · Public = `GlobalAnchorLog`.

**Cross-boundary permissioned invitation (the unifying primitive):** membership is NOT fixed to
space type. Every space has an initiator/admin granting scoped, permissioned access across borders
(guest/member/partner/cross-org = same mechanism, different scope). Safe because: every invitee is a
verified human; every grant is a **provenance event** (cryptographic, auditable — who admitted whom,
at what level, when), not a DB flag; an admin can only invite across borders they can cross;
permissions compose and don't leak upward.

---

## 4. Credentialed news feed & endorsements (a Commons shape)

**Thesis applied to information: the platform surfaces verifiable claims; it never scores credibility.**
No algorithm, no fact-checker, no engagement optimization. Chronological / user-ordered.

- **Author credential** — a verifiable credential (`ps_credential`) issued by an accredited **Org**
  (APA credentials doctors, press orgs credential journalists). Held by the author's persona.
- **Org-credentials-people IS the accreditation-delegation authority** (§2 sharp edge #1): issuer has
  its own key; the issuer is itself accredited (Guild chain); viewer verifies `author ← APA ←
  accreditation` and decides what each link is worth.
- **Endorsement / review** = a signed **provenance event** (Vouch) by an org on a post/persona/space.
- **Top-3 endorsers** = the author's **user-curated selective presentation** (choose which verifiable
  endorsements to feature); platform never picks; viewers verify each against the issuer's key.
- **Trust roots are the user's choice** — no default authority list the platform can weight.
- **"Verified human ✓"** badge on posts from a certified persona — proves *a real, unique person said
  this* **without** revealing who. Novel property.

---

## 5. Market / Vouch & "no unauthorized sales"

- **A review is a receipt.** No verified purchase → no review, provably. Verified human + verified
  purchase + cryptographic binding = a review that can't be faked or bought. The act = **Vouch**,
  always Public-ledgered.
- **No unauthorized sale, system-wide (LOCKED invariant).** A sale is a rights-gated attested event;
  to pass the deterministic gate it must prove: **seller accountable** (verified-human bound,
  real-ID-disclosable) + **provable rights** to the thing (authored it via provenance, or holds a
  license permitting resale) + **attested terms**. No rights → the sale never executes → no receipt.
  One gate, every commerce path routes through it.

---

## 6. Atlas as plug-in substrate (don't rebuild what exists)

**Atlas is the trust substrate everyone plugs into — not a competitor to any of them.**

| They do | Plug into Atlas as | Atlas adds |
|---|---|---|
| C2PA / Content Credentials | provenance **format** (emit/consume) | "verified live human" assertion + ledger anchor |
| Truepic | capture **source** | binding to a verified-human identity |
| Transcrypts | credential **issuer/verifier** | selective disclosure + personhood + your-vault custody |
| OpenAI / Anthropic / open weights | inference **provider** behind the gate | consent/rights enforcement + non-custody placement |
| Cloud / home nodes | storage **provider** | ciphertext-anywhere (only encrypted shards) |
| Payment rails · W3C VC · IdP | **adapters** | verified-human + provenance envelope |

**The architecture already supports this** — seams/contracts everywhere (Wearable seam, attestation
contract, threshold ciphertext-anywhere, deterministic gate, credential-scheme interface,
content-agnostic provenance). **Invariant:** plug-ins are **untrusted by default; the substrate
constrains them** — a plugged-in model only sees gated data; a plugged-in node holds only ciphertext;
a plugged-in issuer's credentials are anchored + selectively disclosable. *Interop, not rebuild.*

---

## 7. Media architecture

### 7.1 Provenanced content viewer (content-agnostic)
Provenance signs **bytes, not file types** — media AND PDFs/docs relate identically:
- **Camera media** (live-captured) → liveness **+ anti-spoof PAD** = *"real scene, not a deepfake."*
- **Authored content** (PDF/text/report/contract) → authorship + signature + liveness + anchor,
  **no camera PAD** = *"a verified live human authored these bytes."* (Applies to forged docs, fake
  reports, AI papers — arguably the bigger use case.)

Brick: **one viewer** rendering any vault item (image/video/audio/PDF/text) with the verified-human
**badge** (`accountable` = integrity+handle+signature+liveness+anchored) and a **view count**.
*Gap found:* capture currently stores files in the generic vault **without** persisting provenance —
wiring provenance onto stored items is step 1.

### 7.2 View analytics — sybil-resistant, aggregate, non-surveilling
A view = a PoLE-gated event with a per-`(viewer, item)` **nullifier** (`space_nullifier` pattern) →
count **distinct verified humans** (no bot inflation) **without identifying anyone**. Creator gets
honest reach; viewer is a nullifier, not a name. *Mechanism now (local); network-wide tally is
downstream of the node network.*

### 7.3 Security — the real surface is the DECODER, not a browser
- **No executable content in a space (LOCKED bright line).** Spaces hold **declarative data rendered
  by Atlas's own renderer**; there is **never a general-purpose interpreter in the loop** — no
  `WKWebView` running arbitrary JS, no `eval`, no embedded active content, no "just this once"
  scripting. This kills the entire browser/XSS/JS class **by construction**. The day Atlas gains a
  scripting capability, the guarantee is void.
- **But killing executable content does NOT kill the media-parser surface** — the FORCEDENTRY class
  (a malicious *image/PDF* exploiting the C system decoder, **zero-click**) is what has actually owned
  iPhones. Provenance proves *who*, **not that the bytes are safe to decode.** All media untrusted
  regardless of author.
- **Decode-isolation constraint (LOCKED):**
  - untrusted media **never** touches the C system codecs — **memory-safe decoders only** (this
    *prevents* the exploit class; the load-bearing defense, since a 3rd-party iOS app can't fully
    replicate Apple's BlastDoor process isolation);
  - decode in the most-sandboxed context available, with **zero** reach to vault/keys/System-ID/
    enclave/network;
  - only **validated, sanitized output** crosses back.

### 7.4 Cleaning / sanitization (CDR) — split by who may see the plaintext
**Principle: whoever cleans it must decode it → must see it. So only let people see what they're
allowed to.** (Don't "reject" media — sanitize: decode-in-isolation + transcode + validate.)

- **Public / hosted content** → cleans **anywhere on the network** (decentralized, earns
  **Proof-of-Compute**; it's public, so a volunteer node leaks nothing). Scales.
- **Private / E2E content** → cleans on **owned nodes** or **on-device** (never handed to untrusted
  volunteers). Decentralized private cleaning would require a **TEE** on the node (hardware-trust-root
  + side-channel tradeoff).
- **Sender-side sandbox (enclave-enforced)** is the primary gate: outgoing device sanitizes before
  seal; the Secure Enclave will only produce the send-seal for content carrying a valid
  "passed-the-genuine-sanitizer" attestation → sanitization is a **mandatory attested step**, not
  optional. **Recipient on-device isolation is the backstop** (can't assume every sender device is
  honest even on an honest-only network — attestation has 0-days; honest-at-admission ≠ forever).
- **Trusted HSM'd holding-tank nodes** (owned): clean on the box you own & trust — **no TEE needed to
  hide it from yourself.** **HSM = key custody; TEE = blind compute** (only needed on hardware you
  *don't* own, or to promise users "even Atlas can't see it"). **Relay stays fully blind for E2E peer
  traffic**; the cleaning node is a *separate lane* that is trusted-to-see the content it cleans.
  Keep the honest banner accurate about which lane content took.

---

## 8. Node network, storage & the 3-jurisdiction backbone

- **SE-gated, honest-only admission** (attested device) + **PoLE-gated** (verified human; anti-sybil;
  **no dedicated mining, no compute bought purely to earn**; home nodes are human-operated by design).
- **Untrusted-by-default network**; **any storage works because everything is encrypted Shamir shards**
  (`threshold_seal` ciphertext-anywhere — no node holds enough to read anything).
- **3 HSM'd nodes (Toronto / London / Tokyo)** for the **most important secrets** (LK/epoch-witness,
  global-anchor signing, recovery/OPRF key shards), jurisdiction-sharded (**anti-collusion**: must
  break multiple jurisdictions at once). Matches the patent's jurisdiction-sharded HSM model.
- **HONEST GAP — the distributed-systems layer is the big net-new build:** encryption gives
  *confidentiality* on untrusted nodes (solved). It does **not** give availability/durability
  (replication + erasure coding), integrity (proofs-of-retrievability), retrieval (DHT/addressing), or
  non-equivocation (drand + public chain + checkpoints). **Everything media-heavy and economy-heavy is
  downstream of this network existing.** Don't claim audience-scale hosting or the token economy as
  day-one.

---

## 9. Data / AI economy & tokens (from the provisional, roadmap-honest)

- **Base "mining" = Proof of Living Entropy (PoLE)** — not work, not stake. Resource = living
  (human/environmental) entropy; distribution = all living participants (patent p490/p503).
- **Two-tier issuance:** **UBI floor** (80% of validated PoLE emissions → global pool, cost-of-living
  indexed) + **Variable Rewards** (verified participation/improvement/stewardship). Harmful activities
  ineligible by rule.
- **Proof of Compute** (p360) — home-node compute/storage contribution, **PoLE-gated** (no reward
  without a live human). The reward hook for the node network. *(The honest first brick to build.)*
- **Deterministic rights/consent gate upstream of every model** — checks provenance + rights + consent
  at **access time**; fails → the model never sees the datum. *Deterministic decides; generative
  obeys, never given the choice.* Inside Atlas the gate **enforces**; outside Atlas provenance is
  **evidence**, not enforcement.
- **Data flip-forward-only + grandfathering** — pricing flag lives **on the datum**, checked at access;
  free grants already taken stay free, every new access after a flip is paid. Both enforced by crypto,
  no trusted admin.
- **Keep data where consent lives** — prefer retrieval / federated over central ingestion so the corpus
  stays provenanced and **revocable**; consented/public data ONLY, **never the sealed vault**.
- **Orgs pay for ACCESS, never for the humans.** Surveillance-model line held.
- **BYO-model = non-custody applied to AI:** local open-weights model for private data (sealed vault →
  **local model only**, never a 3rd-party API); external models for consented/public data (retrieval
  over training). **AI companies = pluggable compute AND customers** (they license the clean corpus).

---

## 10. Build sequence

**Day-one-real (substrate exists):** text/pages/spaces/messaging/provenance/vault/market/credentials.
**Downstream (node-network-gated):** distributed storage/replication/retrieval, decentralized private
cleaning, token economy, audience-scale media, deterministic gate at scale, personal AI.

| Phase | Deliverable | Notes |
|---|---|---|
| **A (now)** | Finish **provenanced content viewer** (media+PDF+badge+view count) + wire provenance onto stored items | `AtlasSession` plumbing done (parked); reference-first |
| **A.1** | **Fix mailbox handle** → persona/disclosure-tier slice (off root `systemIDHandle`) | corrects `2576b75` |
| **B** | **`Space` object** (constructor over `spaces/space.py`) + persistence modes + persona membership | Self/Direct/Commons = shapes |
| **C** | **Proof-of-Compute** attested-proof hook (PoLE-gated) | reward-layer anchor |
| **D** | **Cross-boundary invitation / accreditation authority** | **design + adversarial pressure-test FIRST** (privilege-escalation edge) |
| **E** | **Credentialed feed / Commons** + endorsements + top-3 | multi-issuer credentials |
| **F** | **Media-decode isolation** (memory-safe decode + sandbox) + cleaning lanes | before shipping media hosting |
| **↓** | Node network (discovery/replication/retrieval/proofs), token economy, personal AI, audience-scale media | downstream |

Each phase: **reference-first (Python is source-of-record), mirrored to Swift + parity, tested.**

---

## 11. Security invariants (LOCKED)

1. **THE USER CHOOSES** — non-custody; no un-overridable platform defaults.
2. **Truth recoverable, not harm prevented** — the provable thesis; the honest banner never over-claims.
3. **Accountable pseudonymity** — bound for accountability, disclosed only under authorized cause.
4. **No unauthorized sale, system-wide** — rights-gated attested event; deterministic decides.
5. **Verification ≠ safety** — provenance proves *who*, never that bytes are safe to execute/decode.
6. **No executable content in a space** — declarative data, Atlas's own renderer, never an interpreter.
7. **Untrusted media never touches C system codecs** — memory-safe decode, isolated, zero-secret-reach.
8. **Deterministic decides / generative & providers obey** — gate upstream, never given the choice.
9. **Attested, not trusted** — and state *which* blindness a lane actually delivers (crypto vs TEE vs
   trusted-node).
10. **Plug-ins untrusted by default; the substrate constrains them.**

**Three sharp edges to design most carefully:** (1) permissioned-invitation/accreditation authority,
(2) deterministic rights/consent gate, (3) media-decode isolation.

---

## 12. Audit readiness

The core (identity/provenance/threshold/messaging/ledger) is a working, tested **prototype** — credible
to hand to top auditors. The broader platform is **design**, not built; hold both truths.

**Before commissioning:** (1) freeze + tag the audited scope; (2) commission **specialist cryptography
review** for the novel *compositions* (OPRF/threshold/identity/provenance glue) **+** a general
security firm — **multiple independent**; (3) hand them a **threat model + real-vs-modeled inventory**
(honest boundaries are already in docstrings). AI review (Claude Code `/security-review`,
`/code-review`, `ultrareview`) = continuous first-pass, **not** a substitute for human/formal audit —
especially on the novel crypto.
