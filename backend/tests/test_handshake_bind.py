"""Handshake bind — the random-N ring-tap must match the challenge, co-occur across
phone-IMU / ring-IMU / mic, and land at the Face-ID instant, or it fails closed."""
from atlas.liveness.handshake_bind import detect_taps, verify_handshake


def test_detect_taps_finds_the_impulses():
    # 100 Hz signal, quiet with three sharp spikes at ~0.5s, 1.0s, 1.5s
    fs = 100.0
    sig = [0.02] * 200
    for idx in (50, 100, 150):
        sig[idx] = 3.0
    taps = detect_taps(sig, fs=fs, threshold=1.0)
    assert len(taps) == 3
    assert abs(taps[0] - 0.5) < 0.02 and abs(taps[2] - 1.5) < 0.02


def test_valid_handshake_binds():
    face = 10.0
    phone = [9.6, 9.9, 10.2, 10.5]
    ring = [9.61, 9.9, 10.19, 10.51]      # same 4 taps, tiny per-device offset
    assert verify_handshake(phone_taps=phone, ring_taps=ring, requested_n=4, faceid_at_s=face) is True


def test_wrong_count_fails():
    # user produced 3 taps but the random challenge asked for 4
    assert verify_handshake(phone_taps=[9.7, 10.0, 10.3], ring_taps=[9.7, 10.0, 10.3],
                            requested_n=4, faceid_at_s=10.0) is False


def test_misaligned_ring_fails_same_body():
    # ring taps don't co-occur with the phone taps -> not one hand / one contact
    phone = [9.6, 9.9, 10.2, 10.5]
    ring = [9.6, 9.9, 10.2, 12.0]         # last tap 1.5s off — different device/hand
    assert verify_handshake(phone_taps=phone, ring_taps=ring, requested_n=4, faceid_at_s=10.0) is False


def test_taps_outside_faceid_window_fail():
    # right count + aligned, but nowhere near the Face-ID instant (replay from earlier)
    phone = [0.6, 0.9, 1.2, 1.5]
    ring = [0.6, 0.9, 1.2, 1.5]
    assert verify_handshake(phone_taps=phone, ring_taps=ring, requested_n=4,
                            faceid_at_s=100.0, window_s=6.0) is False


def test_mic_corroboration():
    phone = [9.7, 10.0, 10.3]
    ring = [9.71, 10.0, 10.29]
    mic_ok = [9.7, 10.0, 10.3]
    mic_bad = [9.7, 10.0]                  # mic missed a tap
    assert verify_handshake(phone_taps=phone, ring_taps=ring, requested_n=3,
                            faceid_at_s=10.0, mic_taps=mic_ok) is True
    assert verify_handshake(phone_taps=phone, ring_taps=ring, requested_n=3,
                            faceid_at_s=10.0, mic_taps=mic_bad) is False


def test_zero_requested_rejected():
    assert verify_handshake(phone_taps=[], ring_taps=[], requested_n=0, faceid_at_s=10.0) is False
