# Atlas — canonical naming / glossary

The single source of truth for what each term means. Several words were overloaded
(the same name pointed at two different objects), which caused real confusion. This
file fixes the vocabulary. When code and this file disagree, this file is the intent
and the code should be renamed toward it (see "Known overloads" below).

Each entry gives: **what it is**, **its role**, and **prototype status** (what is
real vs. stubbed today).

---

## The load-bearing invariant (read first)

**Value = QRNG. Liveness/timing GATES and TIMES; it never enters a key/value.**
Keys and values are clean random (QRNG). Living signals (PoLE, ambient change,
entropy) decide *whether* and *when* an operation happens and *when* a fresh value
is drawn — they are never folded *into* a value. "Biology times; QRNG values."
Aggregating **values** (e.g. combining LKs) is allowed; aggregating **timing** is
not.

*Prototype note:* all QRNG is **device RNG** (`randomBytes`/`os.urandom`) standing
in for a real quantum source.

---

## Keys & the unwrap chain

### epoch id
- **What:** a *public* label (8 bytes) that binds derivations to a specific epoch
  (rotation window). Not secret.
- **Role:** appears in every derivation (`seed_chain`, session-key KDF, wraps) so
  material from one epoch can't be mistaken for another.
- **Code:** `epoch_round` / `epochRound` everywhere — the 8-byte round index from the
  epoch beacon (`EpochRound.epoch_round()` / `BeaconRound.epoch_round()`). Renamed
  this session from the old misnomer `drand_round`, which wrongly implied external
  drand was the epoch key (it is not — see "epoch key").
- **Prototype status:** real. The round index is the public label carried through
  every derivation (`seed_chain`, session-key KDF, wraps).

### epoch key
- **What:** a per-epoch **QRNG value sampled by aggregating the current LKs across
  the LKG regional nodes**. Network-derived, rotating, unpredictable, controlled by
  no single node. This is the "network-public" per-epoch value.
- **Role:** the **only thing that unwraps the LK** for this epoch. "Current" is
  load-bearing — an old epoch key cannot unwrap the current LK.
- **Code:** the value — `epoch_key` / `epochKey` (`presence.wrap_lk`/`unlock_lk`,
  `wrap_epoch_key`/`unwrap_epoch_key`; Swift `Presence.wrapLK`/`unlockLK`,
  `wrapEpochKey`). The published beacon that carries it — `EpochBeacon` (backend
  `beacon/epoch.py`, Swift `Beacon/EpochBeacon.swift`): fires the QRNG epoch on
  aggregate LK-arrival timing (random cadence), monotonic index, aggregator-signed.
- **Not drand.** External drand (`beacon/drand.py`) is only the BOOTSTRAP timeline
  and a defence-in-depth ANCHOR bound into the signature — never the epoch key and
  never folded into any value.
- **Prototype status:** the **wrap relationship is real**, and the **aggregator now
  exists** as `EpochBeaconService` (`beacon/epoch_service.py`) — the LKG aggregator
  that holds the signing key and fires the signed epoch. It runs on Atlas's own
  servers; relays and phones only CONSUME + VERIFY it (`EpochBeaconClient`,
  `AtlasNode.beacon_now`, verified against the pinned aggregator key). Still stubbed:
  the iOS `AtlasRuntime.establishEpoch` path uses a local `randomBytes(32)`, and real
  collector-node LK arrivals aren't fed in yet (the node uses stand-in arrival
  timing). The N=2 co-derivation (below) remains the stand-in for full regional LK
  aggregation.

### LK — Living Key
- **What:** the **system-wide private** living secret. It can only be unwrapped
  with the **current epoch key**.
- **Role:** the private value that, once unwrapped, feeds the session key. Being
  system-wide + current-epoch-bound ties it to being a live participant *now*.
- **Code:** `lk` / `LK`. Co-derivation: `live_lk.co_derive_lk` / `LiveLK.coDeriveLK`.
- **Prototype status:** two shapes exist today (see "Known overloads"): a
  single-device `randomBytes(32)` stub in the on-device presence path, and a
  **co-derived** LK in the two-phone run (both phones' fresh halves HKDF'd, order-
  independent). The co-derived N=2 case is the stand-in for the full regional-LKG
  aggregation of the system-wide LK.

### LKG regional nodes
- **What:** the regional Living-Key nodes whose **current LKs are aggregated to
  sample the epoch key**. The aggregator that samples/signs the epoch from their
  arrivals is `EpochBeaconService` (Atlas-server infrastructure, holds the signing
  key); collector nodes feed it LK arrivals.
- **Role:** decentralize the epoch key's entropy so no single node controls it.
- **Prototype status:** the aggregator **service exists** (`beacon/epoch_service.py`,
  signed epoch rounds, drand as bootstrap/anchor), but the regional collector-node
  network is not built — a single device (or the N=2 phones) stands in for it, and
  the node feeds stand-in arrival timing rather than real LK arrivals.

### enrolment secret
- **What:** a secret sealed in the **Secure Enclave**, released ONLY on live
  presence (biometric/Face ID + PoLE operating).
- **Role:** the presence root. Access to the current epoch key is gated behind it:
  the epoch key is wrapped to the enrolment secret, so you must be live+present to
  obtain it.
- **Code:** `enrolment_secret` / enrolment seal; `enclave.seal/release`.
- **Prototype status:** real logic; the on-device seal is the real SE, the backend
  models it (`ModelEnclave`).

### session key
- **What:** the working key for a live session.
- **Role:** `SessionKey = HKDF(PoLE_value, LK, epoch_key, prev_key, context)` — each
  input is independent (the epoch key contributes the epoch binding, the LK the
  living secret, PoLE the liveness moment, prev_key the chain).
- **Code:** `derive_session_key_decoupled` / `Derivation` (Swift).
- **Prototype status:** real.

### channel key
- **What:** the pairwise ML-KEM-768 + X25519 shared secret from the KEM handshake
  between two participants.
- **Role:** seals the message envelope so the relay node stays blind, AND is one of
  the seeds of the message ratchet ("static keys for who-you-are").
- **Code:** `channel_key` / `channelKey` (`seed_chain`, `FSRelayClient`).
- **Prototype status:** real (ran in the two-phone demo).

### PoLE / PoLE value
- **What:** Proof-of-Living-Entropy. The **PoLE value** is the clean QRNG value
  fired at a liveness moment; the **PoLE gate/state** (`operate`) is the Bayesian
  liveness decision.
- **Role:** the value is a KDF input; the gate decides whether operations proceed
  (fail-closed). The gate NEVER enters the value.
- **Code:** `pole` / `PoLEState`, `fire_pole_value`, `LivenessGate`.
- **Prototype status:** real; on the phone the gate is now driven by real ambient
  change (see continuity ratchet).

---

## Ratchets (there are TWO — never say bare "ratchet")

### message ratchet
- **What:** a per-message **one-way forward-secret hash chain** (Signal symmetric-
  key style). Each `seal`/`open` derives a fresh message key and advances the chain,
  discarding the old key.
- **Role:** forward secrecy per message within an epoch. Deterministic, so both
  sides ratchet in lockstep with no per-message secret sent.
- **Honest boundary:** symmetric hash chain, NOT a DH double-ratchet — forward
  secrecy, but no post-compromise "future secrecy." `beacon_t`/`epoch_round` folded in
  are constant across the epoch.
- **Code:** `fs_conversation.step` / `FSConversation.step`, `conversation.py` /
  `Conversation.swift`, `device.message_ratchet_step`.
- **Prototype status:** real — THIS ran in the two-phone demo.

### continuity ratchet
- **What:** the **ambient-timed, presence-gated epoch/continuity advance**. Live
  ambient presence times the interval and gates the step; a fresh QRNG value is
  folded per step.
- **Role:** keeps the session "only as old as the last live tick"; a liveness break
  wipes/zeroizes (fail-closed).
- **Code:** `timed_ratchet_step`, `device.continuity_tick`, `RatchetClock`;
  Swift `timedRatchetStep`, `continuityTick`.
- **Prototype status:** real, but exercised by the **Ambient tab**, NOT by the two-
  phone messaging. The two are **not composed yet** (see "Open integration").

---

## Liveness entropy (GBSS — Math Spec v1.4)

### GBSS entropy vector — h_i / s_i / m_i / c_i
- **What:** structured liveness assessment. `h_i` HRV/PPG/GSR (involuntary
  biomechanical), `s_i` IMU motion variance, `m_i` micro-interaction
  (touch/keystroke/voice), `c_i` contextual/environmental (ambient).
- **Role:** each channel scored by the entropy operators into a density; aggregated
  into a per-window liveness density feeding the PoLE gate. **Measurement only —
  never a key/value.**
- **Code:** `liveness/gbss.py`, `liveness/entropy.py`; Swift `Liveness/GBSS.swift`,
  `Entropy.swift`.
- **Prototype status:** `s_i` + `c_i` real on the phone, partial `m_i`; **`h_i` is
  ring-deferred (None on phone)** — the involuntary core is the R10 ring's job.

### entropy operators
- **Shannon** (average unpredictability), **min-entropy** (worst-case, the hard
  anti-loop gate), **Lempel-Ziv complexity** (anti-loop/compressibility), **spectral
  entropy** (waveform structure). All measurements; never keyed.

### change-based ambient signal
- Ambient presence is **change, not level**: each snapshot XOR'd against the
  previous (baseline cancels); entropy across snapshots gates loops/replays. Drives
  the PoLE liveness gate. See `signal_source.py` / `SignalSource.swift`.

---

## Blind relay
- **Mac node** = a **blind relay**: two phones share a key it never holds; it
  stores/forwards **opaque ciphertext** and sees only envelope metadata (from/to,
  size, order). Separate opt-in public path for content the user chooses to publish.
- **Code:** `net/node_server.py`; Swift `FSRelayClient`.

---

## Known overloads (what this file fixes)

1. **"epoch key" pointed at two things:** the public **epoch id** (label) vs the
   secret **epoch key** (network-aggregated LK-wrapper). They are different objects.
   Verbally, always say "epoch id" or "epoch key," never the ambiguous "epoch key"
   when you mean the label.
2. **"the ratchet" pointed at two things:** the **message ratchet** (per-message FS,
   ran in the demo) vs the **continuity ratchet** (ambient-timed epoch advance, ran
   in the Ambient tab). Always qualify.
3. **"LK" has two provenances today:** the single-device **stub** LK vs the
   **co-derived** LK. Both are the Living Key; the stub is what the co-derivation
   (and ultimately the regional-LKG aggregation) replaces.

### Optional code rename (not yet done)
To make the code read like this glossary: `epochKey → epochWrapKey` (or keep
`epochKey` but never call the label a "key"), and label the two ratchets
consistently. Deferred until the two subsystems are composed (below), so the rename
happens once.

---

## Open integration (the honest gap)

The two-phone run validated the **co-derived-LK + message-ratchet** slice. It did
NOT run the **epoch-key-from-regional-LKG** provenance or the **continuity ratchet**,
and those two subsystems are not yet composed. The target: the continuity ratchet
advances epochs; each epoch's LK is co-derived live (regionally aggregated at scale)
and unwrapped under a **current epoch key sampled from the LKG nodes**, presence-
gated; that LK feeds the message ratchet.

### ⚠ To confirm (LK privacy guarantee)
The epoch key is network-public yet must keep the system-wide LK private. Pin which
holds: (a) the **wrapped-LK blob is never public** (stays on-device/regional),
and/or (b) an **additional presence gate** on the unwrap (must be live+present in
the current epoch). The code currently relies on (b) — the epoch key is wrapped to
the presence-released enrolment secret. Confirm the intended guarantee and update
this section.
