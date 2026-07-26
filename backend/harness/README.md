# Atlas hardware-test harness (debug-parallel)

A guided, self-documenting test rig for real-device runs with **one operator + the ring +
the flash drive + the iPhone + the Mac**. The iPhone runs the real app (real BLE driver,
Secure Enclave, gate, attestation) and — in a **DEBUG build only** — streams a parallel
telemetry channel to the Mac. Local Claude Code, running on the Mac, drives the session:
it prompts you through each physical phase, captures the phone's live telemetry, scores it
against the **real backend thresholds**, and appends audit-grade entries to a results file.

This exists to close the recording gap: instead of "run the test and remember to write it
down," every run is captured, scored, and logged automatically.

## What is and isn't in the loop

- **In the loop (genuine):** ring → CoreBluetooth → Secure Enclave → gate → attestation.
  The tests exercise the production path, not a Mac re-implementation.
- **Observe-only:** the debug channel *reports* what the on-device gate computed. It never
  feeds samples into the gate, and it is wrapped in `#if DEBUG` so it cannot ship. Tap,
  don't feed.
- **Operator = physical actuator.** Claude prompts ("wear the ring", "ring on the mug",
  "remove now"); you act; the harness captures and scores. Nothing here can move the ring
  or fabricate a signal — if the phone streams nothing, a phase scores **no telemetry**,
  never a pass.

## Pieces

| File | Role |
|---|---|
| `protocol.py` | The telemetry contract (newline-delimited JSON schema). |
| `ios_debug_emitter.swift` | Reference DEBUG-only emitter to wire into the iOS app. |
| `collector.py` | Stdlib TCP server; buffers phone telemetry by arrival time. |
| `scoring.py` | Pass/fail scorers using real `atlas.*` thresholds (PI_STAR, SAME_BODY_FLOOR, 3s wipe budget). |
| `runner.py` | Interactive guided session; prompts phases, scores, logs. |

## Run it (on the Mac, devices active)

1. Wire `AtlasDebugEmitter` into the iOS app where the gate updates, and start it in a
   DEBUG build with the Mac's LAN IP:
   `AtlasDebugEmitter.start(host: "<mac-lan-ip>", port: 7731)`
2. On the Mac:
   ```bash
   cd backend
   python -m harness.runner --results ../HARDWARE_RUN_$(date +%Y%m%d).md
   # single test:  python -m harness.runner --only "removal"
   ```
3. Follow the prompts. Read the results file when done; re-run any phase that scored FAIL.

Local Claude Code can invoke `runner.py`, read the emitted results file, and iterate with
you turn by turn.

## Coverage

Drives the gap-closing subset: sensitivity (T1), rejection/specificity (T5–T7), removal +
wipe latency (T10/T11), same-body true case (T30). The flash-drive recovery and duress
tests are pure software and already covered by the backend suite; the tap-bind, real App
Attest, and multi-party tests remain gated on streaming-IMU hardware / a dev account /
more devices (unchanged by this harness — the R10's intermittent accel is the limit there,
not the rig).
