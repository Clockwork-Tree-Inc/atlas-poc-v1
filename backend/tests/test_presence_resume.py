"""Presence lifecycle + resumption codes — a Bluetooth blip resumes on the right code;
a swap, a wrong code, a timeout, or a replayed code all fail closed to LOCKED."""
import pytest

from atlas.crypto.primitives import random_bytes
from atlas.session.presence_resume import (
    PresenceSession, PresenceState, resume_code,
)


def _sess(grace_s: float = 30.0):
    return random_bytes(32), 0.0


def test_resume_codes_are_deterministic_per_side_and_swap_cannot_forge():
    bind = random_bytes(32)
    # ring and phone derive the SAME code independently from the shared bind secret
    assert resume_code(bind, 0) == resume_code(bind, 0)
    # each counter is a distinct one-time code
    assert resume_code(bind, 0) != resume_code(bind, 1)
    # a different (swapped/spoofed) ring's secret produces different codes
    assert resume_code(random_bytes(32), 0) != resume_code(bind, 0)


def test_blip_resumes_within_grace_on_correct_code():
    bind = random_bytes(32)
    s = PresenceSession(bind, at_s=0.0, grace_s=30.0)
    assert s.operating()
    s.disconnect(at_s=10.0)
    assert s.state is PresenceState.SUSPENDED and not s.operating()
    # ring reconnects 5s later with the next code -> resumes
    assert s.reconnect(resume_code(bind, 0), at_s=15.0) is True
    assert s.state is PresenceState.PRESENT and s.operating()


def test_wrong_code_locks():
    bind = random_bytes(32)
    s = PresenceSession(bind, at_s=0.0, grace_s=30.0)
    s.disconnect(at_s=5.0)
    assert s.reconnect(b"\x00" * 16, at_s=6.0) is False
    assert s.state is PresenceState.LOCKED
    assert s.lock_event.reason == "bad_code"


def test_reconnect_after_grace_window_locks():
    bind = random_bytes(32)
    s = PresenceSession(bind, at_s=0.0, grace_s=30.0)
    s.disconnect(at_s=5.0)
    # even the CORRECT code is refused once the window has passed
    assert s.reconnect(resume_code(bind, 0), at_s=40.0) is False
    assert s.state is PresenceState.LOCKED
    assert s.lock_event.reason == "timeout"


def test_check_timeout_locks_after_window():
    bind = random_bytes(32)
    s = PresenceSession(bind, at_s=0.0, grace_s=30.0)
    s.disconnect(at_s=5.0)
    assert s.check_timeout(at_s=20.0) is False       # still inside the window
    assert s.state is PresenceState.SUSPENDED
    assert s.check_timeout(at_s=40.0) is True         # window elapsed
    assert s.state is PresenceState.LOCKED and s.lock_event.reason == "timeout"


def test_replayed_old_code_is_rejected():
    bind = random_bytes(32)
    s = PresenceSession(bind, at_s=0.0, grace_s=30.0)
    # first blip resumes on code 0 -> counter advances to 1
    s.disconnect(at_s=5.0)
    assert s.reconnect(resume_code(bind, 0), at_s=6.0) is True
    # second blip: replaying the OLD code 0 must fail (expected is now code 1)
    s.disconnect(at_s=10.0)
    assert s.reconnect(resume_code(bind, 0), at_s=11.0) is False
    assert s.state is PresenceState.LOCKED and s.lock_event.reason == "bad_code"


def test_two_blips_consume_successive_codes():
    bind = random_bytes(32)
    s = PresenceSession(bind, at_s=0.0, grace_s=30.0)
    s.disconnect(at_s=5.0)
    assert s.reconnect(resume_code(bind, 0), at_s=6.0) is True
    s.disconnect(at_s=10.0)
    assert s.reconnect(resume_code(bind, 1), at_s=11.0) is True   # next code in the chain
    assert s.operating()


def test_lock_is_terminal_no_auto_recovery():
    bind = random_bytes(32)
    s = PresenceSession(bind, at_s=0.0, grace_s=30.0)
    s.remove(at_s=1.0)
    assert s.state is PresenceState.LOCKED and s.lock_event.reason == "removed"
    # a fresh pulse does NOT silently un-lock (re-presence is a new session)
    s.pulse(at_s=2.0)
    assert s.state is PresenceState.LOCKED
    # reconnect on a locked session is a no-op refusal
    assert s.reconnect(resume_code(bind, 0), at_s=3.0) is False


def test_empty_bind_secret_rejected():
    with pytest.raises(ValueError):
        PresenceSession(b"", at_s=0.0)
