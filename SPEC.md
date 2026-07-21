# Atlas Protocol — Specification (skeleton, v0.1)

> **Status: draft skeleton for review.** This document states the protocol as
> *implemented* in the `backend/atlas/` reference (the reference-of-record), in a
> form meant to be **attacked**. Where a construction is precise in the code, it is
> precise here. Where a property is not yet formally argued, it is marked
> **[needs formal treatment]** rather than glossed. Clause references (§) point at
> the Math Spec (design notes); file references point at the running code.
>
> If you are here to break something, skip to [§12 What to attack](#12-what-to-attack).

---

## 1. Scope and one-sentence thesis

Atlas binds cryptographic capability to a **live, present human** without storing
any biometric template and without a central authority. One anonymous root generates
unlinkable per-context pseudonyms; a live physiological signal **times and gates**
the cryptography; every feature runs under one enrolled identity + live presence.

**The load-bearing invariant (§2.3, "the one principle"):** the living signal
**times** when values are drawn and **gates** whether operations proceed — it
**never enters a key or value**. *Biology times; randomness values.* Any construction
in which raw physiology is folded into key material is non-conformant.

This document specifies the **built + tested** core. Designed-but-unbuilt tiers
(economy, satellite entropy, on-network governance, AI tiers) are out of scope here.

## 2. Notation and primitives

| Symbol | Meaning | Code |
|--------|---------|------|
| `H(·)` | protocol hash, SHA3-256, unframed concat | `crypto/primitives.py` |
| `hkdf(ikm, info, salt, len)` | HKDF-SHA256 | `crypto/primitives.py` |
| `hkdf_combine(...)` | HKDF with **length-prefixed** inputs (domain-rigorous) | `crypto/primitives.py` |
| AEAD | AES-256-GCM, 96-bit nonce | `crypto/primitives.py` |
| KEM | hybrid **ML-KEM-768 + X25519**, X-Wing-*style* combiner | `crypto/kem.py` |
| Sig | hybrid **ML-DSA-65 + Ed25519**; **SPHINCS+/SLH-DSA** root | `crypto/sign.py` |
| Beacon | drand **quicknet** (BLS threshold, unchained-G1), pinned PK | `beacon/drand.py` |
| Randomness | OS CSPRNG (`os.urandom`) | `crypto/primitives.py` |

**Note on `H` vs `hkdf_combine`:** `H` concatenates without length-prefixing —
adequate only for fixed-length inputs (handles, pseudonyms). Variable-length inputs
that must be unambiguous use `hkdf_combine` (length-prefixed). Mixing these up is a
canonicalization bug; see §12.

**KEM combiner caveat (explicit):** the hybrid KEM follows the X-Wing *shape*
(ML-KEM-768 + X25519, with the X25519 public key and the ML-KEM ciphertext folded
into the final KDF) but uses HKDF-SHA256 as the combiner and is **not bit-compatible
with the RFC X-Wing draft**. Interop requires both ends use this exact combiner.

## 3. Threat model and security goals

**Adversary.** A network adversary who sees all wire traffic and controls the relay
(the relay is **honest-but-curious at most**, and is designed to see only ciphertext
+ envelope metadata). Endpoint compromise is treated per-property (below).
Out of scope for the software core: a fully compromised host OS, and hardware
side-channels — these are explicitly deferred to the hardware bring-up + external
audit (see `HARDWARE_TESTING.md`).

**Goals (each links to the section that argues it):**

1. **Presence-gating** — no session key without a live, enrolled, present human (§7).
2. **Containment / forward secrecy** — key compromise at time *t* does not read
   traffic before *t* or after the next ratchet (§6).
3. **Unlinkability** — distinct pseudonyms of one root are unlinkable, incl. against
   a quantum adversary for the hash/HKDF-derived paths (§8).
4. **Accountable attribution** — published content is bound to a verified-human
   pseudonym, resolvable to the System-ID only under cause (§10).
5. **Relying-party authentication** — prove "a live present human authorized *this*
   action to *this* RP", phishing/relay-resistant (§9).
6. **No biometric template stored; no biometric identification performed** (§5).

**Explicit non-goals / honest boundaries** (stated so they are not mistaken for
claims): PAD is an **advisory** signal, not proof the scene is real (analog hole);
traffic-analysis resistance (sealed-sender / mixing) is designed, not built; the
recognition tunnel gives **outsider** resistance, not both-endpoints resistance (§9).

## 4. Identity tree

`keys/identity.py`. The permanent **True-Self Key (TSK)** is ONE key, **split** into
a user-held half (the Atlas Card / possession factor) and a server-HSM-held half
(non-exportable). **There is no separate System-ID secret** — the System-ID is
*reassembled* from both halves; neither half alone reassembles it.

```
TSK (permanent; split user-half + server-HSM-half — never whole post-genesis)
  └─ System-ID   (reassembled from BOTH halves; blind, never surfaced)
       └─ pseudonyms  (forward-derived; PUBLIC / PRIVATE / ANONYMOUS tier each)
```

- Standing identifier: `handle = H("atlas/handle", public)`. Per-context pseudonymity
  derives a different handle per context/tier.
- The full public key is revealed **only** at a continuity event; the verifier checks
  it hashes to the known handle, then verifies the signature.
- **One-to-one verification**, never identification: assert a handle (selector) →
  retrieve that one identity → match live biometric 1:1. The blind root is never
  exposed.

## 5. Liveness gate (PoLE)

`liveness/bayes.py`. A running Bayesian gate integrates per-sample likelihoods:

```
P(L|S) = P(S|L)·P(L) / [ P(S|L)·P(L) + P(S|¬L)·(1−P(L)) ],   P(L) ~ Beta(a0,b0)
```

The posterior from one sample is the prior for the next. **Operate iff P(L|S) ≥ π\***
(default π\* = 0.95). The `Beta(a0,b0)` prior is the personal reference accumulated
during a calibration window (§6) — **not** a stored template of a person; it is a
prior over *aliveness*, and no raw biometric is transmitted (only proof objects).

```
PoLE_state = H( P(L|S)_current || sensor_digest || epoch )   [Tier-3: no ring_SE_sig]
```

**Tier-3 note:** the canonical `PoLE_state` includes a ring secure-element signature;
a commodity ring (Colmi R10) cannot produce one, so the Tier-3 digest omits it and the
phone's enclave signature stands in. **[needs formal treatment]** the likelihood model
`P(S|L)`, `P(S|¬L)` is a heuristic calibrated on synthetic streams; real-PPG
calibration and the resulting error rates are an open hardware task (`HARDWARE_TESTING.md`
seam (c)).

## 6. Key hierarchy, session key, and ratchet

`keys/derivation.py`. The session key (the one principle, made concrete):

```
SessKey = HKDF( PoLE_value, LK, epoch_key, prev_key, context_separator )
```

- `PoLE_value` — a physiologically-**timed** *clean QRNG* value: the live ring signal
  times *when* the device QRNG fires; the fired value is clean randomness (raw
  physiology never enters it).
- `LK`, `epoch_key` — clean QRNG values, present **only because** continuity gated
  their unwrap (§7).
- **No** continuity flag, **no** raw physiology, **no** drand in the value.

Forward-secret ratchet (§2.2):

```
K[t+1] = HKDF( K[t] || H(entropy_t) || beacon_t || drand_round )
```

`SessKey` is **RAM-only** and destroyed on liveness break / logout / attestation
failure / epoch boundary; `SessionKey.destroy()` zeroises, and containment tests
assert a destroyed key cannot decrypt.

**Three decoupled clocks** (`params.py`): device continuity ratchet (10 s ± 2,
jitter = enrolled ring signal), population LK (30 s ± 5, server), public epoch key
(~1 min, drand). Each consumes its beacon **fresh** at its tick — **no caching**; a
missing/stale beacon makes the device **inert (fail-closed)**, never a fallback to a
cached value. The biological jitter **times** the firing; it is never an RNG and never
enters a value.

## 7. Presence-conditioned unwrap (the structural gate)

`session/presence.py`. Presence is enforced **structurally**, not by a skippable
"if present" check:

```
enrolled-live-user + continuously-present
  → Secure Enclave releases the enrollment secret
  → unwrap the current (wrapped) epoch key
  → access LK → ratchet.
```

The epoch key is delivered **wrapped** (AEAD to the device's enrollment secret). The
enclave releases that secret **only** on a live biometric match while PoLE operates.
No presence → no release → the AEAD unwrap **mathematically fails** → no epoch key →
no LK → no ratchet. There is no code path to a session key that bypasses the unwrap.
**Honest boundary:** the enclave-gated release is *modelled* in software
(`keys/enclave.py`); on device it is the real Secure Enclave releasing a key under
biometry (hardware-gated; audit item).

## 8. Pseudonyms and unlinkability

`realid/pseudonym.py`, `realid/ps_credential.py`, `crypto/kem.py`.

- **Persona ↔ persona unlinkability is hash/HKDF-derived**, therefore **post-quantum**:
  distinct pseudonyms of one root stay unlinkable even against a quantum adversary.
- **Anonymous credential:** a pure-Python **Pointcheval–Sanders** scheme behind a
  swappable scheme interface (`credential_scheme.py`), shielded inside the ML-KEM+X25519
  PQC tunnel (`pqc_tunnel.py`). Holder-disclosure is absolute — a designated-opener /
  involuntary-opening extension is **rejected**, not deferred.
- **Honest classical residue** (the only not-yet-PQ part): the anonymous credential's
  *same-credential multi-show* unlinkability and the discrete-log range-proof
  *soundness*. STARK migration is the stated path for the latter. **[needs formal
  treatment]**: the multi-show unlinkability argument and the PS-scheme security
  reduction as composed here.

## 9. Recognition and the evolving tunnel

`session/recognition.py`.

```
recognition      = HKDF( SessionKey_1, SessionKey_2, beacon )       [contributions exchanged as X25519 publics]
tunnel_key[next] = HKDF( tunnel_key[prev], recognition[this_epoch] )
```

Each device derives a per-epoch X25519 ephemeral **from its own session key**; the
public halves are the on-wire contributions; the beacon folds in so recognition
advances when the beacon advances. Symmetric rooting: contributions enter the HKDF in
canonical sorted order (neither device leads).

**Honest threat boundary (corrected after review):** this is a Diffie–Hellman-style
agreement. The provable property is **outsider resistance** — a party with *neither*
session key cannot compute recognition. It is **not** true that "only something holding
*both* keys" can: **either** endpoint's session key plus the public wire traffic
reconstructs the tunnel. That is the normal 2-party-agreement bound (compromise an
endpoint → compromise its pairwise tunnel); forward secrecy + epoch re-keying exist to
contain it. MITM is ruled out by an in-person `bootstrap_tunnel_key` PSK and a
compared **safety number** (see `HANDOFF_LIVE_LK.md`); omitting the PSK **fails closed**
(fresh per-device random root, no convergence).

## 10. Verified-human authenticator (relying party)

`auth/relying_party.py`, `auth/webauthn.py`. Passkey/WebAuthn-*shaped*, presence-strong:

- **REGISTER** — user enrolls an authenticator public key (an authorship pseudonym)
  with the RP.
- **AUTHENTICATE** — RP issues a challenge for an action; Atlas returns an assertion
  signed over `(relying_party, action, challenge)`, **gated by live presence** and,
  for high-assurance actions, a hardware **step-up** (YubiKey fingerprint).
- Phishing/relay-resistant: the assertion **binds the RP**, so a proof for one site
  cannot be replayed to another. Fail-closed: no presence, or a required step-up
  absent, yields no assertion. Atlas never sees RP secrets; the RP never gets Atlas
  keys. Higher assurance ("a verified real human is behind this pseudonym, without
  revealing who") composes the Real-ID inherited proof unchanged.

## 11. Provenance and accountable attribution

`provenance/capture.py`, `provenance/live_binding.py`, `provenance/pad.py`.

Published content is bound to a verified-human pseudonym at a drand-anchored time. The
inherited verification proof's nonce is **bound to (author, content, epoch)** — a
proof for another author/content is rejected (closes the "verification-proof
transplant" finding). The liveness attestation `challenge` is bound to
`(author, content, epoch)` and checked at verify (no cross-capture replay).
**PAD is advisory** — the load-bearing guarantee is *accountable attribution*, not
"the scene is real"; the analog hole is explicitly not claimed.

## 12. What to attack

The properties whose failure would matter most, and where the arguments are thinnest.
Findings → `SECURITY.md` (private) or open a discussion.

1. **The one-principle claim** (§2.3, §6): show any path where the timing/physiology
   digest measurably enters a value or KDF output (it should not). `params.py`
   `COMMIT_INTERARRIVAL_TIMING=False` is the switch; prove it leaks anyway.
2. **Presence unwrap bypass** (§7): find a code path to a `SessKey` that does not go
   through the AEAD epoch-key unwrap.
3. **Recognition beyond its stated bound** (§9): we claim *outsider* resistance only.
   Break *that* (compute recognition with neither session key), or show the safety
   number fails to catch a MITM when the PSK is present.
4. **Canonicalization** (§2): find a variable-length input hashed by unframed `H`
   where two distinct inputs collide in a security-relevant field.
5. **Unlinkability** (§8): link two pseudonyms of one root; or break the multi-show
   unlinkability of the PS credential as composed.
6. **Containment** (§6): read epoch *e−1* ciphertext with an epoch *e* key, or recover
   a destroyed `SessKey`.
7. **Attribution transplant** (§11): make content authored by A pass as authored by B.
8. **AEAD nonce** (Info): 96-bit random nonces on long-lived vault keys — quantify the
   birthday bound and propose the rotation policy.

## 13. Parameters (frozen PoC defaults)

All in `params.py`; overridable as a unit via `ProtocolParams`.

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `PI_STAR` | 0.95 | operate iff P(L|S) ≥ π\* |
| `RATCHET_NOMINAL_S` / `_JITTER_S` | 10 / ±2 | device continuity ratchet (jitter = ring signal) |
| `EPOCH_LENGTH_FLOOR_S` / `_CAP_S` | 3 / 30 | beacon epoch replay window |
| `RECOGNITION_WINDOW_EPSILON_S` | 2.0 | "present together" tolerance |
| `TUNNEL_ROOTING` | symmetric | neither device leads |
| `COMMIT_INTERARRIVAL_TIMING` | **False** | timing never enters a value |

---

## Provenance of this document

This skeleton is generated from the reference implementation's own module
documentation and verified against the running code; it is intended as the starting
point for a spec cryptographers and formal-methods researchers can attack and extend.
Known-answer parity vectors (`backend/parity/parity_vectors.json`) pin the Python and
Swift implementations to the same constructions. Corrections and challenges are
explicitly welcome — that is the point of publishing it.
