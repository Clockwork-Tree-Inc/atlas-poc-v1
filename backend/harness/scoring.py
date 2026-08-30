"""Pass/fail scorers for the N1 hardware tests, evaluated over a phase's telemetry.

Thresholds come from the real backend (`atlas.params`, `atlas.liveness.*`) so the
harness scores against the SAME numbers the on-device gate uses — no drift between
"what the test asserts" and "what the code enforces". Each scorer takes the list of
TelemetryEvents captured during a phase and returns a Verdict.

These scorers read the on-device verdicts the phone already computed (operate flag,
removal_state, key_wiped, same_body_r). They deliberately do NOT recompute liveness
from raw samples — the whole point of keeping the iPhone in the loop is that the real
enclave/gate produced these, and the harness is the witness, not a second gate.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from atlas.params import PI_STAR
from atlas.liveness.cross_device import SAME_BODY_FLOOR
from harness.protocol import TelemetryEvent


@dataclass
class Verdict:
    passed: bool
    detail: str
    n: int                       # events considered
    extra: Optional[dict] = None


def _gate_events(evs: List[TelemetryEvent]) -> List[TelemetryEvent]:
    return [e for e in evs if e.p_live is not None]


# --- sensitivity: the gate should OPEN for a live wearer -------------------
def scores_live(evs: List[TelemetryEvent], *, min_p: float = PI_STAR,
                frac_required: float = 0.80) -> Verdict:
    g = _gate_events(evs)
    if not g:
        return Verdict(False, "no gate telemetry in window", 0)
    ok = [e for e in g if (e.p_live or 0.0) >= min_p]
    frac = len(ok) / len(g)
    passed = frac >= frac_required
    return Verdict(passed,
                   f"{len(ok)}/{len(g)} ticks >= PI_STAR({min_p}); frac={frac:.2f} "
                   f"(need {frac_required})", len(g),
                   {"frac_operate": frac})


# --- specificity: the gate should STAY CLOSED for a non-live source --------
def rejects_nonlive(evs: List[TelemetryEvent], *, max_p: float = PI_STAR,
                    tolerated_frac: float = 0.05) -> Verdict:
    """PASS iff essentially no tick reaches operate. `tolerated_frac` allows a couple
    of transient spikes as the object settles, but the phase must not sustain operate."""
    g = _gate_events(evs)
    if not g:
        return Verdict(False, "no gate telemetry in window (did the phone stream?)", 0)
    breached = [e for e in g if (e.p_live or 0.0) >= max_p]
    frac = len(breached) / len(g)
    passed = frac <= tolerated_frac
    return Verdict(passed,
                   f"{len(breached)}/{len(g)} ticks reached operate; frac={frac:.2f} "
                   f"(tolerate <= {tolerated_frac})", len(g),
                   {"frac_operate": frac})


# --- removal / containment: key must wipe within a latency budget ----------
def wipes_on_removal(evs: List[TelemetryEvent], *, removal_marker_rx: float,
                     budget_s: float = 3.0) -> Verdict:
    """Given the harness arrival time of the physical removal, PASS iff a key_wiped
    (or removal_state in {SUSPICIOUS, LOCKED}) event arrives within budget_s."""
    def is_wipe(e: TelemetryEvent) -> bool:
        return bool(e.key_wiped) or (e.removal_state in ("SUSPICIOUS", "LOCKED"))

    wipes = [e for e in evs if is_wipe(e) and e.rx_t is not None
             and e.rx_t >= removal_marker_rx]
    if not wipes:
        return Verdict(False, f"no wipe/lock within window after removal", len(evs))
    first = min(w.rx_t for w in wipes)  # type: ignore[type-var]
    latency = first - removal_marker_rx
    passed = latency <= budget_s
    return Verdict(passed,
                   f"wipe at +{latency:.2f}s (budget {budget_s}s)", len(evs),
                   {"latency_s": latency})


# --- same-body (true case): phone<->ring motion should correlate -----------
def same_body_holds(evs: List[TelemetryEvent], *, floor: float = SAME_BODY_FLOOR,
                    frac_required: float = 0.60) -> Verdict:
    r = [e.same_body_r for e in evs if e.same_body_r is not None]
    if not r:
        return Verdict(False, "no same_body_r telemetry (needs ring+phone motion)", 0)
    ok = [x for x in r if x >= floor]
    frac = len(ok) / len(r)
    passed = frac >= frac_required
    return Verdict(passed,
                   f"{len(ok)}/{len(r)} windows >= SAME_BODY_FLOOR({floor}); "
                   f"frac={frac:.2f}", len(r), {"frac_above_floor": frac})


# --- generic: assert a removal_state was reached (e.g. VOLUNTARY on dock) ---
def reached_state(evs: List[TelemetryEvent], state: str) -> Verdict:
    hits = [e for e in evs if e.removal_state == state]
    return Verdict(bool(hits), f"{len(hits)} events in state {state}", len(evs))
