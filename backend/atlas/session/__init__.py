"""Session layer: device node, recognition/tunnel, vault, send modes (§4, §9)."""

from .vault import Vault
from .duress_vault import PanicVault, UnlockResult, VaultZeroized
from .signal_source import (
    SignalSource, LiveSignalSample, AmbientSensorSource, RingSignalSource,
    SignalSourceUnavailable, TimedTick, timed_ratchet_step,
)
from .recognition import (
    RecognitionContribution,
    recognition_value,
    evolve_tunnel_key,
)
from .device import Device, EpochInputs, ContinuityTick, PresenceRequired, establish_hybrid_tunnel
from .cadence import RatchetClock
from .onboarding import Onboarding, EnrollmentAuthority, IdentifiedUser, PhaseError
from .tunnel import SendMode, seal, open_message, Message

__all__ = [
    "Vault",
    "PanicVault",
    "UnlockResult",
    "VaultZeroized",
    "SignalSource",
    "LiveSignalSample",
    "AmbientSensorSource",
    "RingSignalSource",
    "SignalSourceUnavailable",
    "TimedTick",
    "timed_ratchet_step",
    "RecognitionContribution",
    "recognition_value",
    "evolve_tunnel_key",
    "Device",
    "EpochInputs",
    "ContinuityTick",
    "PresenceRequired",
    "establish_hybrid_tunnel",
    "RatchetClock",
    "Onboarding",
    "EnrollmentAuthority",
    "IdentifiedUser",
    "PhaseError",
    "SendMode",
    "seal",
    "open_message",
    "Message",
]
