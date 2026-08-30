"""Beacons and the QRNG-timing loop (§3).

Three roles (§3.2):
  * Public beacon / EPOCH KEY -> the LKG aggregator's QRNG epoch (`epoch.py`,
    `EpochBeacon`). Fired on aggregate LK-arrival timing (random cadence),
    published with a monotonic epoch index and signed by the aggregator. This is
    the epoch key — NOT drand.
  * Private beacon / Living Key (LK) -> the presence-fired Server-QRNG stand-in
    (`qrng.py`). Fired by aggregate device arrival-timing; the value is clean QRNG.
  * External drand (`drand.py` real client, `local_beacon.py` offline stand-in) ->
    BOOTSTRAP (a public timeline before the aggregator has fired) and
    DEFENCE-IN-DEPTH ANCHOR only. It is never the epoch key and never a value input.
"""

from .base import Beacon, BeaconRound
from .epoch import EpochBeacon, EpochRound, verify_epoch_round
from .epoch_service import EpochBeaconService
from .local_beacon import LocalBeacon
from .qrng import ServerQRNG, ArrivalTiming

__all__ = ["Beacon", "BeaconRound", "LocalBeacon", "ServerQRNG", "ArrivalTiming",
           "EpochBeacon", "EpochRound", "verify_epoch_round", "EpochBeaconService"]
