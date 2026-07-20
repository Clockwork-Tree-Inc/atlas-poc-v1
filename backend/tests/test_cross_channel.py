"""Cross-channel coherence: a live pulse appears at the same rate in the PPG and the
accelerometer BCG; a spoof that fakes PPG but not a rate-aligned BCG fails closed."""

import math
import random

from atlas.liveness.cross_channel import (
    cross_channel_live,
    dominant_rate_bpm,
    pulse_coherence,
)

FS = 50.0            # Hz
DUR = 8.0            # seconds
N = int(FS * DUR)


def _wave(bpm, amp=1.0, phase=0.0, noise=0.05, seed=0):
    rng = random.Random(seed)
    f = bpm / 60.0
    return [amp * math.sin(2 * math.pi * f * (i / FS) + phase) + rng.uniform(-noise, noise)
            for i in range(N)]


def _flat(noise=0.02, seed=0):
    rng = random.Random(seed)
    return [rng.uniform(-noise, noise) for _ in range(N)]


# --------------------------------------------------------------------------- rate extraction
def test_dominant_rate_recovers_the_pulse():
    bpm = dominant_rate_bpm(_wave(72), FS)
    assert bpm is not None and abs(bpm - 72) < 6


def test_flat_channel_has_no_rate():
    assert dominant_rate_bpm(_flat(), FS) is None


# --------------------------------------------------------------------------- coherence
def test_live_ppg_and_bcg_agree():
    ppg = _wave(72, seed=1)
    accel = _wave(72, amp=0.3, phase=0.7, seed=2)      # BCG at the SAME rate, offset phase
    assert pulse_coherence(ppg, accel, FS)
    assert cross_channel_live(ppg, accel, FS, spo2=98.0, skin_temp_c=33.0)


def test_spoof_ppg_without_bcg_fails():
    ppg = _wave(72, seed=1)
    accel = _flat(seed=3)                              # replayed PPG, no wrist recoil
    assert not pulse_coherence(ppg, accel, FS)
    assert not cross_channel_live(ppg, accel, FS)


def test_mismatched_rates_fail():
    ppg = _wave(72, seed=1)
    accel = _wave(120, amp=0.3, seed=2)               # BCG at a DIFFERENT rate
    assert not pulse_coherence(ppg, accel, FS)


# --------------------------------------------------------------------------- vitals bands
def test_out_of_band_vitals_fail_closed():
    ppg = _wave(72, seed=1)
    accel = _wave(72, amp=0.3, phase=0.7, seed=2)
    assert not cross_channel_live(ppg, accel, FS, spo2=70.0)          # hypoxic / spoof
    assert not cross_channel_live(ppg, accel, FS, skin_temp_c=15.0)   # cold object
    # absent channels (None) don't block a coherent live pulse
    assert cross_channel_live(ppg, accel, FS, spo2=None, skin_temp_c=None)
