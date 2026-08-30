# Hardware results — the lab notebook

Companion to [`HARDWARE_TESTING.md`](HARDWARE_TESTING.md) (the runbook: procedures and
PASS thresholds). This file is the **lab notebook**: what has actually been run, on what
kit, with what outcome — dated, with the measured result. Entries are append-only; each
future run adds an entry rather than editing history.

**Honest framing, up front.** The runs below are *functional* validation on cooperative
users — they demonstrate the stack works end-to-end with real physiology at the bottom
(the sensitivity arm), plus one measured **rejection** result (ring off-body). They do
**not** yet fully measure the specificity arm: spoof rejection rates, replay resistance,
and same-body binding under an adversary actually trying. Those are the next runs (see
"Next live tests" below), and no claim here should be read as covering them. n=2 is n=2.

**Honesty rule (from the runbook):** a seam is recorded `✅ PASS` only when it meets the
runbook's pass definition, on hardware, with the number written down. A software-only
proof is marked `[sw]` and never counts as the hardware pass for a seam whose claim is
physical.

---

## Kit

| Item | Details |
|------|---------|
| Phones | 2 × iPhone (physical devices; models/iOS versions: fill in per entry) |
| Rings | 2 × Colmi R10 (commodity PPG smart ring, BLE; treated as **untrusted open sensor** per the repo's §0.3 posture — no secure element, nothing depends on trusting it) |
| Relay | Mac node (`backend/atlas/net/node_server.py`) as blind relay on LAN |
| Recovery media | Commodity USB flash drive (Lexar) — portable-share path |
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

### R-002 — Live liveness gate on real PPG (acceptance + rejection + removal)
*2026-07-25 — on-device iPhone + Colmi R10, via the in-app "Seams" harness on the `RingProbe` path; results pulled off the device container (`hardware_results.md`)*

Live signals from the R10 — real PPG from real bodies, not the simulation harness —
drove the pipeline hard enough to bootstrap **PoLE values**, gate the **liveness
state**, and run the **epoch engine** (biology-timed ratchet) on device. Measured:

- **Liveness acceptance (worn): ✅ PASS ×8** — live pulse reliably detected on-finger,
  via the ring's PPG-oscillation presence signal (`RingProbe`), not the Bayesian P(L|S)
  gate directly. First real-PPG evidence toward issue #10.
- **Liveness rejection (inert desk): ✅ PASS** — ring on the desk → no live PPG → gate
  stays closed. Needs a >5s settle after removal (residual pulse false-fails a rushed
  attempt); auto-settle (sustained-5s-clear) added to the harness.
- **Containment (removal detection): removal detected 2.2 s** after the last live pulse
  via a 2 s no-pulse watchdog (≤3 s). *This characterizes ring-signal **staleness
  detection**, NOT the session key-wipe (a separate layer).* The R10's presence flag
  freezes on removal (event-driven), so a timer-driven watchdog is required to catch it.

**Demonstrated:** on real hardware, the gate **opens for a live human, stays closed for
an inert object, and detects removal in ~2 s.** **Not demonstrated:** spoofed/warm-object
source, replayed stream, wrong-body rejection — that is seam (c)'s other half and is
queued below. (Engineering note: fixed a Swift-6 `dispatch_assert_queue` crash —
CoreMotion was delivered off the main actor; diagnosed from the on-device crash `.ips`.)

### R-003 — Same-body binding: NOT TESTABLE on the R10
*2026-07-25*

Same-body binding (phone IMU × ring accel vs `SAME_BODY_FLOOR` = 0.4) could not be
exercised: the R10 streams **zero** accelerometer frames (even under vigorous motion),
so the correlation has no ring signal (n=0). This is the honest evidence that same-body
binding — the layer that actually rejects a *second live body* — needs a **streaming-IMU
wearable** (the same limit that defers the tap-bind). It is NOT a liveness failure: a
live wrist correctly *passes* liveness; rejecting the *wrong* body is this binding layer,
which this ring cannot exercise. A best-effort on-device arm (phone CoreMotion × ring
accel) reports `insufficient ring-accel (n=0)` — the R10 confirms the requirement rather
than meeting it.

### R-004 — Portable recovery-share threshold (software + physical USB)
*2026-07-23*

Run against the real `atlas.recovery.threshold_seal` (2-of-3; carriers = drive/phone/Mac):

- **Software arm `[sw]`: ✅ PASS 4/4** — reconstruct from any 2; 1 share →
  `ThresholdNotMet`; wrong user-half → `UnsealFailed` (no oracle). Real share files
  written for the physical arm.
- **Physical USB arm: ✅ PASS 3/3** (Lexar USB) — the `flashdrive.share` was copied to
  the drive and **read back off the removable media** for reconstruction. Recovers from
  USB + phone (digest matches original); survives USB loss (phone + Mac); the USB share
  alone → `ThresholdNotMet` (fail-closed). Test share removed from the drive and the
  volume ejected afterward. **This is the hardware confirmation of R-004.**

### R-005 — Relay blindness (informal observation)
*July 2026 (exact date: fill in)*

Throughout the above runs, the relay/server handled **only encrypted payloads** — no
plaintext, no key material observable server-side.

**Status: informal.** This was an operator observation, not an adversarial capture. The
formal version — full packet capture, key-material hunt, replay + MITM attempts per
runbook seam (h) — is queued below. Metadata (who↔whom, timing, sizes) is visible to
the relay by design and is out of scope of the blindness claim.

---

## What this evidence establishes — and what it doesn't

- **Establishes:** the protocol stack runs end-to-end on physical devices with real
  biology as the timing source; the happy path is real, not simulated; the blind-relay
  architecture functions with content encrypted before it reaches the server; the gate
  opens for a live human, stays closed for an inert object, and detects removal in ~2 s;
  and the recovery threshold reconstructs from real removable media and fails closed.
- **Does not establish:** full discrimination. A gate that opens for live humans and
  closes on an *inert* object has been shown; a gate that closes on a *spoofed/warm*
  source, a *replayed* stream, or the *wrong body* has not yet been measured. Sensitivity
  with only partial specificity is a case report, not a diagnostic. The runs below exist
  to fix exactly that.

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
   distinguishes the cases and at what confidence. *(Blocked on a streaming-IMU wearable
   — see below; the R10's zero-accel stream cannot drive this.)*
5. **Seam (e) — containment timing.** Measured key-wipe latency on liveness break
   (distinct from the R-002 ring-signal staleness detection). PASS: 100% of trials
   wiped ≤ 3 s.
6. **Seam (j) — battery budget.** One full day of ring + app in normal use; record
   incremental drain.

**Evidence discipline for every run:** date, device models + OS versions, app commit
hash, trial counts, raw captures where applicable (pcaps, logs) retained privately, and
a one-line result appended to the results table in `HARDWARE_TESTING.md`. A filled-in
table with attached evidence is the difference between "the founders say it works" and
a lab notebook a skeptic can audit.

---

## Blocked — by capability or account, not quantity

| ID | Seam | Blocked on | Note |
|----|------|-----------|------|
| tap-bind | Same-hand IMU handshake | streaming-IMU wearable (Polar-class) | R10's accel stream is intermittent; a 2nd R10 does **not** help |
| (f) | Real App Attest / DeviceCheck | $99 Apple Developer account | free provisioning stubs it (`appAttestStubbed=true`); not a hardware gap |

## Out of bench scope (needs a pilot, not a kit)

Real Sybil resistance, anti-farm economics, density/colocation — need a **campus pilot
with real people**, not two phones. The bench proves the mechanism; the population claim
needs population. (See `HARDWARE_TESTING.md` "Out of bench scope".)
