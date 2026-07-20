"""ATLAS PoC — ambient signal as the live timing/gating source (iPhone build).

Shows the load-bearing invariant on the reference core: the ambient stream TIMES
the ratchet and GATES it (present -> advance, absent -> inert), while the VALUE
stays clean QRNG — the ambient bytes never enter a key. Swapping the ring in
later is a source swap. Run:  python demos/demo_ambient_signal.py
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from atlas.keys.identity import build_identity_tree
from atlas.liveness.bayes import LivenessGate
from atlas.liveness.synthetic import live_stream
from atlas.session import AmbientSensorSource, RingSignalSource, timed_ratchet_step
from atlas.session import pole as pole_mod
from atlas.session.device import Device

BEACON = b"beacon-fresh" * 3


def banner(t):
    print("\n" + "=" * 68 + f"\n{t}\n" + "=" * 68)


def live_pole():
    g = LivenessGate()
    for _, (psl, psnl) in live_stream(40):
        g.update(p_s_given_live=psl, p_s_given_not_live=psnl)
    return g.state(sensor_digest=b"s", drand_round=b"\x00" * 8)


def main() -> int:
    banner("AMBIENT TIMES, QRNG VALUES — the never-mixed invariant")
    orig = pole_mod.random_bytes
    pole_mod.random_bytes = lambda n: b"Q" * n            # pin the QRNG to show independence
    early = AmbientSensorSource(sampler=lambda: bytes(range(1, 9))).sample()
    late = AmbientSensorSource(sampler=lambda: bytes(range(240, 248))).sample()
    v1 = pole_mod.fire_pole_value(physio_fire_moment=early.timing[0] / 255)
    v2 = pole_mod.fire_pole_value(physio_fire_moment=late.timing[0] / 255)
    print(f"  ambient sample A timing={early.timing.hex()}  B timing={late.timing.hex()}  (differ)")
    print(f"  QRNG pole_value A={v1.hex()[:16]}…  B={v2.hex()[:16]}…  -> IDENTICAL: {v1 == v2}")
    print("  => the ambient bytes set WHEN the draw fires; never WHAT it is.")
    pole_mod.random_bytes = orig

    d = Device("iPhone", build_identity_tree(os.urandom(32)), bootstrap_tunnel_key=os.urandom(32))
    d.advance_epoch_present(lk=b"L" * 32, epoch_key=b"E" * 32, drand_round=b"\x00" * 8)

    banner("PRESENT — live ambient stream times + gates an advancing ratchet")
    ambient = AmbientSensorSource(sampler=lambda: os.urandom(8))   # simulated live stream
    for i in range(3):
        r = timed_ratchet_step(d, ambient, pole=live_pole(), drand_round=b"\x00" * 8, beacon=BEACON)
        print(f"  tick {i}: present, interval={r.interval_s:5.2f}s  advanced={r.tick.operate}  "
              f"key={r.tick.continuity_key.hex()[:12]}…  (source={r.source_kind}, simulated={r.simulated})")

    banner("ABSENT — ambient stream drops -> gate closes -> fail-closed inert")
    dead = AmbientSensorSource(sampler=lambda: b"\x00" * 8)
    r = timed_ratchet_step(d, dead, pole=live_pole(), drand_round=b"\x00" * 8, beacon=BEACON)
    print(f"  gated_out={r.gated_out}  tick={r.tick}  -> ratchet did NOT advance")

    banner("SWAP POINT — the ring is a source swap, no pipeline change")
    try:
        timed_ratchet_step(d, RingSignalSource(), pole=live_pole(), drand_round=b"\x00" * 8, beacon=BEACON)
    except Exception as e:
        print(f"  RingSignalSource deferred: {type(e).__name__}: {e}")
    print("\n  => ambient stands in for the ring's TIMING/GATING role; QRNG values unchanged.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
