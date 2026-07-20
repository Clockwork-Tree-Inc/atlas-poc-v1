# Atlas-PoC

> **A novel machine and method that turns standard, battle-tested classical and post-quantum
> cryptographic primitives into a living, presence-bound trust substrate** — keys that exist
> only while you're alive and present, identity without biometrics, and no central authority.

Proof-of-concept implementation of the Atlas protocol — a post-quantum, live-presence
identity substrate: one anonymous root generates unlinkable per-context pseudonyms, a
live signal *times and gates* the cryptography (it never enters a key), and every
feature (messaging, vault, capture, recovery, authentication) runs under one enrolled
identity + live presence.

**Liveness is not identity.** The live signal proves only that a person is *alive and
present* — and, with a second device, that both sensors are on *one body* right now. It
is checked by the signals' own in-the-moment coherence and cross-device correlation; it
is **never matched against a stored physiological profile of a person**, and Atlas keeps
**no biometric template** and does **no biometric identification**. Physiology only
*times* entropy and *gates* operations. The *who* is bound by the device's own Secure
Enclave biometric (Face ID / Touch ID), whose template never leaves the enclave and which
Atlas never sees or stores. (Note: the "recognition" tunnel is a Diffie–Hellman key
agreement, **not** face recognition.)

## Layout

- **`backend/`** — the Python protocol core + Mac-side node/verifier. The
  **reference-of-record**: every primitive, protocol, and property is defined and
  tested here. Built + tested. See [`backend/README.md`](backend/README.md).
- **`ios/AtlasCore/`** — the Swift port of the crypto core. It **compiles and passes
  its own test suite**, kept byte-for-byte in parity with the Python via shared
  known-answer vectors (`ParityTests`).
- **`ios/AtlasApp/`** — the iOS app (SwiftUI): the one shared session + UI + the
  device-only seams (Secure Enclave, the Colmi R10 ring over BLE, camera/LiDAR). Runs
  on physical iPhones.

## Status

Maturity has three rungs: **built + tested** (runs in this repo, tests pass),
**device-only** (needs a physical iPhone — Secure Enclave, ring, camera — so it's
exercised on hardware, not in CI), and **not built**.

Both the Python core **and** the Swift `AtlasCore` reach **built + tested**:
**CI runs them on every push** — the backend suite (**637 tests**, on the pure-Python
default *and* the native-Ursa path) plus the Swift core/parity suite (**217 tests**) on
macOS. See [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

This is a proof of concept, and it is honest about what is and isn't finished. Where a
seam is a stub or a layer is designed-not-built, it says so plainly below — and because it
is open source (AGPL-3.0), those are **invitations to contribute**, not hidden debt.

| Milestone | Scope | Protocol core | On-device (iOS) |
|-----------|-------|---------------|-----------------|
| 1 | Primitives, beacon/QRNG, derivation+ratchet, recognition tunnel, vault, identity tree | ✅ built + tested (Py + Swift core) | app UI/session source; runs on device |
| 2 | Liveness: R10 BLE pulse, biology-timed ratchet, attestation, removal states | ✅ liveness math built + tested (**sim**) | R10 BLE driver runs on device |
| 3 | In-person enrolment ritual + co-motion ring-lock | ✅ identity/secret construction tested | co-motion + biometric capture on device |
| 4 | Recovery: Enclave (device-present) + portable-share threshold + real-you↔digital-you anchor (total-loss) | ✅ recovery core built + tested | JavaCard path **not built** |
| 5 | Provenance + depth-checked capture | ✅ provenance + PAD core built + tested | camera/LiDAR capture on device |
| 6 | Two send modes incl. verified-human-only viewing | ✅ both modes built + tested | on-device wiring runs on device |

**Beyond the milestone spec — also built + tested:**

- **Live group session** — N named users co-derive **one** live LK through a *blind*
  relay; this ran **end-to-end on two iPhones** with forward-secret group messaging. The
  handshake is identity-authenticated (each KEM key is signed by its author identity) and
  members compare a **safety number** to rule out a man-in-the-middle. See
  [`HANDOFF_LIVE_LK.md`](HANDOFF_LIVE_LK.md).
- **Verified-human authenticator** ([`backend/atlas/auth/relying_party.py`](backend/atlas/auth/relying_party.py)) —
  Atlas authenticates a **person** to a relying party (a bank, a service) over **passkeys**,
  binding liveness + presence to the RP's challenge. It is **NOT a bank / wallet / payment
  rail** — an authenticator existing services can consume over a protocol they already
  speak. Built + tested, with Swift parity. See [`HANDOFF_AUTH.md`](HANDOFF_AUTH.md).
- **Anonymous-credential unlinkability** — a pure-Python **Pointcheval–Sanders** scheme
  (`backend/atlas/realid/ps_credential.py`) behind a swappable credential-scheme seam, so
  the unlinkable verification-inheritance path runs **everywhere** (the archived Ursa BBS+
  is now an optional native accelerator, not a hard dependency).
- **Spaces** (social containers *inside a vault* — not to be confused with the satellite
  *space tier*) — `backend/atlas/spaces/` + `ios/…/Spaces/`: access / identity / persistence
  tiers, content with threaded comments, like/dislike votes, reports, **Sybil-free polls** at
  three anonymity levels, a **receipt-gated market**, and **soul-bound participation tokens**
  (non-transferable, non-monetary). Built + tested on both platforms, with cross-impl parity.
- **BLS-verified drand beacon** — the provenance timestamp root now verifies the drand
  **BLS threshold signature** against the pinned League-of-Entropy public key (not just the
  hash binding), validated against a live round. See `backend/atlas/beacon/drand.py`.

Notes:
- "**built + tested**" = passes in CI: 637 backend tests + the Swift `AtlasCore` suite (217 tests).
  M2's liveness is tested **in simulation** (synthetic streams), not a real ring; M5's PAD
  is tested over **depth/moiré summaries**, not a real camera.
- "**device-only**" = needs a physical iPhone (Xcode, Secure Enclave, CoreBluetooth, camera).
- Provenance's load-bearing guarantee is **accountable attribution** — content bound to a
  verified-human pseudonym, resolvable to the System-ID only under cause — with **PAD
  demoted to an advisory fraud signal** (the analog-hole "is the scene real" problem is
  explicitly not claimed).

**Crypto posture (honest):** the core is **post-quantum** — ML-DSA-65 + Ed25519 signatures,
SPHINCS+ root, ML-KEM-768 + X25519 KEM — and **persona↔persona unlinkability is hash/HKDF-derived,
so it is post-quantum too** (separate identities stay unlinkable even against a quantum adversary).
The classical (not-yet-PQ) residue is narrow: the anonymous credential's *same-credential multi-show*
unlinkability and the discrete-log range-proof *soundness*, with a **STARK migration path** for the
latter. **Not built (designed):** on-network governance, the AI tiers, and the **space *tier***
(satellites — distinct from Spaces). The **economy/token** is designed and its capabilities described,
but the implementation is **not included here** (it is on the patent track).

## Docs

- [`CAPABILITIES.md`](CAPABILITIES.md) — **every capability** of the system, grouped by layer
  and tagged by maturity (built + tested / built / sim / device-gated / designed / vision).
- [`APPLICATIONS.md`](APPLICATIONS.md) — **what the capabilities unlock**, by domain, each
  grounded in the specific capabilities that enable it.
- [`NAMING.md`](NAMING.md) — the **canonical model**, leading with the load-bearing
  invariant: **Value = QRNG; the live/timing signal GATES and TIMES but never enters a
  key or value** ("biology times; QRNG values"). Two clocks, one meaning each: the secret
  **epoch key** and the public **drand** timekeeper.
- [`SECURITY_PRIVACY_REVIEW.md`](SECURITY_PRIVACY_REVIEW.md) — whole-system security &
  privacy audit: dependency/static scans + adversarial subsystem review, findings ranked
  by severity, what's sound, and the open hardware/design items.
- `backend/SECURITY_TESTS.md` — what the tests actually assert (security vs functional).
- `backend/parity/parity_vectors.json` — cross-implementation known-answer vectors
  (Python ↔ Swift); regenerate with `python -m tools.gen_parity_vectors`.
- [`HARDWARE_TESTING.md`](HARDWARE_TESTING.md) — the hardware/red-team runbook with a
  measurable pass/fail for each real-world seam sim can't prove.
- [`REALID_MODULE.md`](REALID_MODULE.md) — identity / real-ID binding / unlinkability /
  duress (test data only); see also [`THREAT_COVERAGE.md`](THREAT_COVERAGE.md).
- [`CREDENTIAL_PQC_POSTURE.md`](CREDENTIAL_PQC_POSTURE.md) — the credential posture:
  classical credential shielded behind the ML-KEM+X25519 PQC tunnel, behind a swappable
  (PQ-ready) scheme interface; holder-disclosure is absolute (designated opener rejected).
- [`PAYMENT_MODULE.md`](PAYMENT_MODULE.md) — the payment add-on: **the air gap is not
  proven in sim**; reviewer + audit sign-off required before any value-bearing use.

## Quick start

```bash
cd backend
pip install -r requirements.txt      # pure-Python by default (Ursa BBS+ is optional)
python -m pytest -q                  # 362 tests
python -m demos.demo_milestone1_text

# Swift core (macOS):  cd ios/AtlasCore && swift test
```

## AI use & authorship

The Atlas invention — its architecture, mechanisms, and design decisions — is the work of the
inventor, **Aun Ali**. AI tools were used for **research, drafting, and implementation assistance
under the inventor's direction**. The ideas and the direction originate with the inventor.

**AI clients used**: Claude, ChatGPT, Perplexity

## Founder's note 

Greetings reader,

It is with great hope that I reveal this design and code. This project started as a return to normal workflow after a prolonged medical disability, as a desire to help other people struggling with disability and mental illness break their bonds. Med school, healing, self discovery, and helping others deal with trauma, illness, and loss has taught me that the gates to freedom lie not in any one plane, but exist dispersed and guarded selfishly, accessible only to the few wielding connection, wealth, and safety. It is difficult to spend time in a position to help others only to feel helpless in the face of apathy, abandonment, danger, disease, and poverty, and Atlas is intended to behave as a bulwark to these ghosts of a fraught past. I invite you to contact us to help us build and fulfill this vision for a brighter future for all of us.

Aun Ali, MBBS
Founder,
Clockwork Tree Inc.

## Notices

**Copyright © 2026 Clockwork Tree Inc.** All rights reserved. The source in this repository is the
work of Clockwork Tree Inc. Commercial licensing: Clockwork Tree Inc.

**Patent pending** — the underlying invention (inventor: **Aun Ali**; assigned to **Clockwork Tree
Inc.**) is the subject of a filed provisional patent application.

**Trademarks** — Atlas™, PoLE™, Renaissance Ecosystem™, and Clockwork Tree™ are trademarks of
Clockwork Tree Inc.

**No surveillance, no manipulation** — Atlas performs no engagement-optimization, behavioral
profiling, or attention-harvesting. The algorithms here are cryptographic, not behavioral.
