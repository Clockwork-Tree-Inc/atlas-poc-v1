# Hardware Test Log — real-device runs

Companion to [`HARDWARE_TESTING.md`](HARDWARE_TESTING.md) (the runbook: procedures and
PASS thresholds). This file is the **lab notebook**: what has actually been run, on what
kit, with what outcome. Entries are append-only; each future run adds an entry rather
than editing history.

**Honest framing, up front.** Everything below is *functional* validation on cooperative
users — it demonstrates the stack works end-to-end with real physiology at the bottom
(the sensitivity arm). It does **not** yet measure the specificity arm: spoof rejection,
removal detection rates, replay resistance under an adversary actually trying. Those are
the next runs (see "Next live tests" below), and no claim here should be read as covering
them. n=2 is n=2.

---

## Kit

| Item | Details |
|------|---------|
| Phones | 2 × iPhone (physical devices; models/iOS versions: fill in per entry) |
| Rings | 2 × Colmi R10 (commodity PPG smart ring, BLE; treated as **untrusted open sensor** per the repo's §0.3 posture — no secure element, nothing depends on trusting it) |
| Relay | Mac node (`backend/atlas/net/node_server.py`) as blind relay on LAN |
| Recovery media | Commodity USB flash drives (portable-share path) |
| Users | n = 2 enrolled live humans (the builders — cooperative, not adversarial) |

---

## Run log

### R-001 — Two-phone live group session through the blind relay
*July 2026 (exact date, device models, app commit: fill in)*

Two named users on two physical iPhones co-derived **one live LK** through the Mac
blind relay and exchanged **forward-secret group messages** end-to-end. The handshake
was identity-authenticated (each KEM key signed by its author identity); members
compared the **safety number** to rule out a man-in-the-middle. This is the run
documented in [`HANDOFF_LIVE_LK.md`](HANDOFF_LIVE_LK.md).

**Demonstrated:** enrolment → live session → group key agreement → messaging, on real
hardware, no simulated seams in the message path.

### R-002 — Real physiological signals drive the engine (no synthetic streams)
*July 2026 (exact date: fill in)*

Live signals from the Colmi R10 rings — real PPG from two real bodies, not the
simulation harness — fed the pipeline hard enough to bootstrap **PoLE values**, gate the
**liveness state**, and run the **epoch engine** (biology-timed ratchet) on device.

**Demonstrated:** the sensor→gate→epoch vertical works on live noisy input, which is
the most common failure point of sensor-driven crypto and cannot be proven in sim.
**Not demonstrated:** rejection behavior (ring off-body, spoofed source, replayed
stream) — that is seam (c)'s other half and is queued below.

### R-003 — Relay blindness (informal observation)
*July 2026 (exact date: fill in)*

Throughout the above runs, the relay/server handled **only encrypted payloads** — no
plaintext, no key material observable server-side.

**Status: informal.** This was an operator observation, not an adversarial capture. The
formal version — full packet capture, key-material hunt, replay + MITM attempts per
runbook seam (h) — is queued below. Metadata (who↔whom, timing, sizes) is visible to
the relay by design and is out of scope of the blindness claim.

### R-004 — Portable recovery-share media exercise
*July 2026 (exact date + procedure + outcome: fill in)*

Commodity USB flash drives were used as the portable-share media for the recovery
path. *(Entry stub — the operators should record here: how shares were written, the
threshold configuration used, whether reconstruction was performed and verified, and on
which device.)*

---

## What this evidence establishes — and what it doesn't

- **Establishes:** the protocol stack runs end-to-end on physical devices with real
  biology as the timing source; the happy path is real, not simulated; the blind-relay
  architecture functions with content encrypted before it reaches the server.
- **Does not establish:** discrimination. A gate that opens for live humans has been
  shown; a gate that *closes* on everything else has not yet been measured. Sensitivity
  without specificity is a case report, not a diagnostic. The runs below exist to fix
  exactly that.

---

## Next live tests (queued, in priority order)

Each maps to a runbook seam with a measurable PASS threshold — see
[`HARDWARE_TESTING.md`](HARDWARE_TESTING.md) for full procedures. All are executable
with the current kit and n=2.

1. **Seam (c) — liveness rejection arm.** Ring on the desk; ring on a warm object;
   ring removed mid-session; ring worn by the *other* enrolled user. PASS: live reaches
   P(L|S) ≥ 0.95 within ≤ 10 s in ≥ 95% of live trials **and** every non-live condition
   stays below threshold. Record trial counts and timings.
2. **Seam (h) — formal wire capture.** Repeat R-001 under tcpdump/Wireshark on the
   relay host. Hunt for key material and plaintext; attempt a recognition-message
   replay; attempt a MITM and confirm the safety-number check catches it. PASS: no
   session key observable; replays rejected; MITM detected.
3. **BLE replay (seam (g) subset).** Capture a ring's BLE stream and replay it to the
   phone. PASS: replayed stream fails the in-the-moment coherence check and does not
   hold the gate open.
4. **Cross-device correlation (one-body check).** Both rings on one body vs. one ring
   each on two bodies claiming co-presence. Record whether cross-device correlation
   distinguishes the cases and at what confidence.
5. **Seam (e) — containment timing.** Measured key-wipe latency on liveness break.
   PASS: 100% of trials wiped ≤ 3 s.
6. **Seam (j) — battery budget.** One full day of ring + app in normal use; record
   incremental drain.

**Evidence discipline for every run:** date, device models + OS versions, app commit
hash, trial counts, raw captures where applicable (pcaps, logs) retained privately, and
a one-line result appended to the results table in `HARDWARE_TESTING.md`. A filled-in
table with attached evidence is the difference between "the founders say it works" and
a lab notebook a skeptic can audit.
