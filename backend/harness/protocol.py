"""Debug-telemetry protocol: the contract between the iOS DEBUG build and the Mac harness.

The iOS app, in a DEBUG build ONLY, opens a plain TCP connection to the Mac harness
and streams newline-delimited JSON objects — one per line, one per telemetry tick.
This channel is OBSERVE-ONLY: it reports what the on-device gate already computed. It
never feeds samples back into the gate, and it never exists in a release build. The
enclave/BLE/attestation path stays exactly as production; the harness only watches.

Each line is one TelemetryEvent (see `to_dict` keys). Unknown keys are ignored so the
schema can grow without breaking older harness runs. Timestamps are the phone's
monotonic clock in seconds (float); the harness stamps its own arrival time too.

Message shape (all keys optional except `t` and `kind`):

    {
      "t":            1234.567,        # phone monotonic seconds
      "kind":         "gate",         # gate | removal | epoch | attest | note
      "p_live":       0.987,           # PoLE posterior P(L|S)
      "operate":      true,            # p_live >= PI_STAR on-device
      "epoch":        42,
      "ppg_bpm":      61.2,            # dominant PPG rate the app computed (or null)
      "bcg_bpm":      60.0,            # dominant accel/ballistocardiogram rate (or null)
      "spo2":         97.0,            # or null if absent
      "skin_temp_c":  33.4,           # or null if absent (R10 temp is slow/coarse)
      "same_body_r":  0.72,           # phone<->ring motion correlation (or null)
      "removal_state":"ACTIVE",       # ACTIVE | VOLUNTARY | SUSPICIOUS | LOCKED
      "key_wiped":    false,           # RAM session key zeroized this tick
      "attest_tier":  "BOUND",        # NONE|PRESENCE|BOUND|ATTESTED|IDENTIFIED
      "note":         "free text"      # for kind == note
    }

The harness never requires all keys; scorers read only what a given test needs.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class TelemetryEvent:
    t: float                              # phone monotonic seconds
    kind: str = "gate"                    # gate | removal | epoch | attest | note
    p_live: Optional[float] = None
    operate: Optional[bool] = None
    epoch: Optional[int] = None
    ppg_bpm: Optional[float] = None
    bcg_bpm: Optional[float] = None
    spo2: Optional[float] = None
    skin_temp_c: Optional[float] = None
    same_body_r: Optional[float] = None
    removal_state: Optional[str] = None
    key_wiped: Optional[bool] = None
    attest_tier: Optional[str] = None
    note: Optional[str] = None
    # harness-side arrival stamp (filled by the collector, not the phone)
    rx_t: Optional[float] = None

    @classmethod
    def from_line(cls, line: str) -> "TelemetryEvent":
        d = json.loads(line)
        # keep only known fields; ignore the rest so the schema can grow
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})

    def to_line(self) -> str:
        return json.dumps({k: v for k, v in asdict(self).items() if v is not None})
