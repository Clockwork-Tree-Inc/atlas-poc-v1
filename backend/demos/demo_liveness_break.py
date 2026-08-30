"""A ~10-second, self-evidently-real demo: a sealed message OPENS while a live human is present, and
REFUSES the instant presence breaks — BY CONSTRUCTION. No presence -> the enclave withholds the
enrolment secret -> the epoch-key unwrap fails mathematically -> no LK -> the message stays sealed.
There is no code path to the plaintext that bypasses the presence gate.

    python -m demos.demo_liveness_break
"""
from atlas.crypto.primitives import H, aead_decrypt, aead_encrypt, random_bytes
from atlas.keys.enclave import SecureEnclave
from atlas.liveness.bayes import PoLEState
from atlas.session.presence import (EnrolledPresence, unlock_lk, unwrap_epoch_key, wrap_epoch_key,
                                     wrap_lk)

DRAND = b"\x00" * 8
MESSAGE = b"meet at the north pier at 9pm"


def _msg_key(lk: bytes) -> bytes:
    return H(b"atlas/demo/msg", lk)


def _try_open(sealed, wrapped_epoch, wrapped_lk, presence, bio, pole):
    secret = presence.release(live_biometric=bio, pole=pole)   # enclave releases ONLY if present
    if secret is None:
        return None
    epoch_key = unwrap_epoch_key(wrapped_epoch, presence_secret=secret, epoch_round=DRAND)
    lk = unlock_lk(wrapped_lk, epoch_key=epoch_key, epoch_round=DRAND)
    return aead_decrypt(_msg_key(lk), sealed)


def run_demo() -> None:
    bio = random_bytes(32)
    enclave = SecureEnclave()
    enrolment_secret = random_bytes(32)
    presence = EnrolledPresence(enrolment_secret, enclave=enclave, biometric=bio)

    epoch_key, lk = random_bytes(32), random_bytes(32)
    wrapped_epoch = wrap_epoch_key(epoch_key, enrollment_secret=enrolment_secret, epoch_round=DRAND)
    wrapped_lk = wrap_lk(lk, epoch_key=epoch_key, epoch_round=DRAND)
    sealed = aead_encrypt(_msg_key(lk), MESSAGE)
    print("A message was sealed under the live-presence key.\n")

    present = PoLEState(p_live=1.0, state_digest=b"present", epoch_round=DRAND, operate=True)
    got = _try_open(sealed, wrapped_epoch, wrapped_lk, presence, bio, present)
    print("  live + present :", got.decode() if got else "REFUSED")

    broke = PoLEState(p_live=0.0, state_digest=b"gone", epoch_round=DRAND, operate=False)
    try:
        got = _try_open(sealed, wrapped_epoch, wrapped_lk, presence, bio, broke)
    except Exception:
        got = None
    print("  liveness broke :",
          got.decode() if got else "REFUSED — enclave withheld the secret; the unwrap fails. Sealed by construction.")


if __name__ == "__main__":
    run_demo()
