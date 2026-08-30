"""Interactive, guided hardware-test runner — the program local Claude Code drives.

It walks the operator (you) through each N1 test one phase at a time: it prints an
instruction, waits for you to act and press enter, captures the iPhone's live debug
telemetry for that phase, scores it against the real backend thresholds, and appends
an audit-grade entry to a results file. That is what turns "run the test and remember
to write it down" into a self-documenting session — killing the R-004-is-a-stub problem.

Run on the Mac (devices active, iOS DEBUG build streaming to this host):

    cd backend
    python -m harness.runner --results ../HARDWARE_RUN_$(date +%Y%m%d).md

Local Claude Code can invoke this directly, read the emitted results file, and iterate.
Physical acts (wear ring / ring on mug / remove ring) are yours; capture+score+log is the
harness's. Nothing here can move the ring or fake a signal — if the phone streams nothing,
a phase scores as "no telemetry", never as a pass.
"""
from __future__ import annotations

import argparse
import time
from dataclasses import dataclass
from typing import Callable, List

from harness.collector import Collector
from harness.protocol import TelemetryEvent
from harness import scoring
from harness.scoring import Verdict


@dataclass
class Phase:
    instruction: str            # what the operator should physically do
    capture_s: float            # seconds of telemetry to collect for this phase
    scorer: Callable[[List[TelemetryEvent], float], Verdict]
    # scorer receives (events_in_window, phase_start_rx) so removal tests can use the marker


def _prompt(msg: str) -> None:
    try:
        input(msg)
    except EOFError:
        # non-interactive (e.g. piped) — proceed without blocking
        print(msg + " [auto-continue]")


def run_phase(collector: Collector, phase: Phase) -> Verdict:
    _prompt(f"\n>>> {phase.instruction}\n    Press ENTER when ready, then hold still...")
    start_rx = time.monotonic()
    print(f"    capturing {phase.capture_s:.0f}s ...", flush=True)
    time.sleep(phase.capture_s)
    window = collector.since(start_rx)
    verdict = phase.scorer(window, start_rx)
    flag = "PASS" if verdict.passed else "FAIL"
    print(f"    [{flag}] {verdict.detail}  (n={verdict.n})", flush=True)
    return verdict


# ---- the N1 test definitions (single body + ring + phone; subset shown) ----
def build_tests() -> "list[tuple[str, list[Phase]]]":
    return [
        ("T1 live enrollment/session bootstrap (sensitivity)", [
            Phase("Wear the ring normally on your finger.", 15.0,
                  lambda evs, s: scoring.scores_live(evs)),
        ]),
        ("T5 ring on desk — must reject", [
            Phase("Take the ring OFF and lay it flat on the desk.", 15.0,
                  lambda evs, s: scoring.rejects_nonlive(evs)),
        ]),
        ("T6 ring on warm object (~skin temp) — must reject on coherence", [
            Phase("Place the ring on a warm mug (skin-temp), not on you.", 15.0,
                  lambda evs, s: scoring.rejects_nonlive(evs)),
        ]),
        ("T7 ring on warm + vibrating object — must reject", [
            Phase("Ring on the warm object while it vibrates/moves slightly.", 15.0,
                  lambda evs, s: scoring.rejects_nonlive(evs)),
        ]),
        ("T10/T11 removal detection + key wipe (<=3s)", [
            Phase("Wear the ring; establish a live session.", 12.0,
                  lambda evs, s: scoring.scores_live(evs)),
            Phase("REMOVE the ring now (this marks the removal instant).", 6.0,
                  lambda evs, s: scoring.wipes_on_removal(evs, removal_marker_rx=s,
                                                          budget_s=3.0)),
        ]),
        ("T30 same-body (true case): phone+ring on one body", [
            Phase("Wear the ring; hold the phone; move around gently for the window.",
                  15.0, lambda evs, s: scoring.same_body_holds(evs)),
        ]),
    ]


def _append_results(path: str, title: str, verdicts: List[Verdict]) -> None:
    passed = all(v.passed for v in verdicts) and bool(verdicts)
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")  # wall clock for the notebook
    lines = [f"\n### {title}", f"*{stamp}*  —  **{'PASS' if passed else 'FAIL'}**", ""]
    for i, v in enumerate(verdicts, 1):
        lines.append(f"- phase {i}: {'PASS' if v.passed else 'FAIL'} — {v.detail} "
                     f"(n={v.n}{'' if not v.extra else '; ' + str(v.extra)})")
    with open(path, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser(description="Atlas N1 guided hardware-test runner")
    ap.add_argument("--host", default="0.0.0.0")  # nosec B104 - LAN bind so the iOS debug build can stream here; pass --host 127.0.0.1 to restrict
    ap.add_argument("--port", type=int, default=7731)
    ap.add_argument("--results", default="HARDWARE_RUN.md")
    ap.add_argument("--only", default=None,
                    help="substring to select a single test by title")
    args = ap.parse_args()

    collector = Collector(host=args.host, port=args.port)
    collector.start()
    print(f"[runner] collector up on {args.host}:{args.port}")
    print("[runner] start the iOS DEBUG build and confirm it connects "
          "(watch the event count).")
    _prompt("Press ENTER once the phone is streaming...")
    print(f"[runner] {collector.count()} events seen so far.")

    tests = build_tests()
    if args.only:
        tests = [(t, p) for (t, p) in tests if args.only.lower() in t.lower()]
        if not tests:
            print(f"[runner] no test matches --only '{args.only}'")
            collector.stop()
            return

    for title, phases in tests:
        print(f"\n========== {title} ==========")
        verdicts = [run_phase(collector, ph) for ph in phases]
        _append_results(args.results, title, verdicts)
        print(f"[runner] logged to {args.results}")

    collector.stop()
    print(f"\n[runner] done. Results in {args.results}. Raw event count: {collector.count()}")


if __name__ == "__main__":
    main()
