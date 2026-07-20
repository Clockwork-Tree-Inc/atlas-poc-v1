"""Beacons and the QRNG-timing loop (§3).

Two beacons (§3.2):
  * Public beacon / epoch key -> drand (`drand.py` real client, `local_beacon.py`
    offline stand-in). Public, fungible, cannot be a per-device secret.
  * Private beacon / Living Key (LK) -> the presence-fired Server-QRNG stand-in
    (`qrng.py`). Fired by aggregate device arrival-timing.
"""

from .base import Beacon, BeaconRound
from .local_beacon import LocalBeacon
from .qrng import ServerQRNG, ArrivalTiming

__all__ = ["Beacon", "BeaconRound", "LocalBeacon", "ServerQRNG", "ArrivalTiming"]
