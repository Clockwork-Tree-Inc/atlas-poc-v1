"""Phone-only anti-bot challenge/response + offline verifier: fresh-challenge binding, replay
rejection (one-shot), wrong-challenge rejection, no-physical-signal rejection, signature check."""

from atlas.crypto.sign import generate_sig_keypair
from atlas.liveness.antibot import (
    LOCK_FREE_TRIES,
    SIDEWAYS,
    UP_DOWN,
    AntiBotVerifier,
    derive_shake_plan,
    issue_challenge,
    lock_backoff_seconds,
    respond,
    shake_plan_digest,
)


def _kp():
    kp = generate_sig_keypair()
    return kp, kp.public


def test_fresh_challenge_response_verifies():
    kp, pub = _kp()
    v = AntiBotVerifier()
    ch = issue_challenge(epoch=1)
    r = respond(ch, motion_summary=b"imu+tap+entropy-digest", keypair=kp, public=pub)
    assert v.verify(r, ch)


def test_replay_rejected_one_shot():
    kp, pub = _kp()
    v = AntiBotVerifier()
    ch = issue_challenge(epoch=1)
    r = respond(ch, motion_summary=b"m", keypair=kp, public=pub)
    assert v.verify(r, ch)          # first use ok
    assert not v.verify(r, ch)      # replay -> nonce consumed -> rejected


def test_response_to_wrong_challenge_rejected():
    kp, pub = _kp()
    v = AntiBotVerifier()
    ch1 = issue_challenge(epoch=1)
    ch2 = issue_challenge(epoch=1)
    r = respond(ch1, motion_summary=b"m", keypair=kp, public=pub)
    assert not v.verify(r, ch2)     # answer bound to ch1 cannot pass ch2 (no replay across challenges)


def test_no_physical_signal_rejected():
    kp, pub = _kp()
    v = AntiBotVerifier()
    ch = issue_challenge(epoch=1)
    r = respond(ch, motion_summary=b"", keypair=kp, public=pub)   # a bare program: no moved device
    assert not v.verify(r, ch)


def test_tampered_signature_rejected():
    kp, pub = _kp()
    other, _ = _kp()
    v = AntiBotVerifier()
    ch = issue_challenge(epoch=1)
    r = respond(ch, motion_summary=b"m", keypair=kp, public=pub)
    r.public = other.public          # claim a different signer -> signature no longer verifies
    assert not v.verify(r, ch)


# --- shake-to-prove-human: RNG-derived plan + escalating lock -----------------

def test_shake_plan_is_deterministic_for_a_nonce():
    nonce = bytes(range(16))
    assert derive_shake_plan(nonce) == derive_shake_plan(nonce)


def test_shake_plan_differs_across_nonces():
    # A fresh nonce yields a different plan (unpredictable / non-precomputable).
    a = derive_shake_plan(bytes([0] * 16))
    b = derive_shake_plan(bytes([1] * 16))
    assert a != b


def test_shake_plan_respects_shape_and_range():
    plan = derive_shake_plan(bytes(range(16)), segments=3, min_count=3, max_count=6)
    assert len(plan) == 3
    for seg in plan:
        assert seg.direction in (UP_DOWN, SIDEWAYS)
        assert 3 <= seg.count <= 6


def test_shake_plan_derived_from_the_challenge_nonce():
    # The plan binds to the fresh challenge issued by the anti-bot protocol.
    ch = issue_challenge(epoch=1)
    p1 = derive_shake_plan(ch.nonce)
    p2 = derive_shake_plan(ch.nonce)
    assert p1 == p2 and shake_plan_digest(p1) == shake_plan_digest(p2)


def test_shake_plan_known_answer():
    # Frozen KAT — the Swift mirror (AntiBotShakeTests) must reproduce these bytes exactly.
    nonce = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plan = derive_shake_plan(nonce)          # defaults: 2 segments, 3..6
    assert [(s.direction, s.count) for s in plan] == [(SIDEWAYS, 4), (UP_DOWN, 5)]
    assert shake_plan_digest(plan).hex() == (
        "54a3d6e3d176d7e2fa8389e0020b4adcb9fe55fc5e1d78e267b70a11de5ce0a7"
    )


def test_lock_backoff_schedule():
    for n in range(0, LOCK_FREE_TRIES + 1):
        assert lock_backoff_seconds(n) == 0          # first 10 failures are free
    assert lock_backoff_seconds(11) == 30
    assert lock_backoff_seconds(12) == 60
    assert lock_backoff_seconds(13) == 120
    assert lock_backoff_seconds(14) == 240
    assert lock_backoff_seconds(100) == 3600         # capped at one hour
    # monotonic non-decreasing
    prev = 0
    for n in range(0, 40):
        cur = lock_backoff_seconds(n)
        assert cur >= prev
        prev = cur


def test_tap_plan_derived_from_nonce_and_kat():
    from atlas.liveness.antibot import derive_tap_plan, tap_plan_digest, TapSegment
    nonce = bytes(range(16))
    plan = derive_tap_plan(nonce)
    assert plan == [TapSegment(count=3), TapSegment(count=3)]          # KAT (Swift parity)
    assert tap_plan_digest(plan).hex() == (
        "71d7e8bda3347a4221f9e77e5f7a0798c5d846ed055c65bbdf0150f3ba480bef")
    # a different nonce yields a different rhythm (unpredictable, non-replayable)
    assert derive_tap_plan(b"\xff" * 16) != plan or tap_plan_digest(derive_tap_plan(b"\xff" * 16)) != tap_plan_digest(plan)
    # bounds respected
    for seg in derive_tap_plan(nonce, segments=5, min_taps=1, max_taps=9):
        assert 1 <= seg.count <= 9
