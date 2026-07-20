"""End-to-end demo: Atlas authenticating a person to a bank (a relying party).

Runs the whole loop in-process so it prints without a network:
  1. LOGIN — a routine challenge, answered with a live, presence-gated assertion.
  2. HIGH-VALUE — a step-up challenge, answered with a YubiKey fingerprint.
  3. RELAY ATTACK — a proof made for the bank is REJECTED by a different site.
  4. NO PRESENCE — a dead liveness gate yields no assertion (fail-closed).

Run: python -m atlas.auth.demo
"""

from __future__ import annotations

import os

from ..keys.hardware_key import YubiKeyBio
from ..keys.identity import build_identity_tree
from ..liveness.bayes import LivenessGate, PoLEState
from ..liveness.synthetic import live_stream
from .relying_party import AuthRefused, RelyingPartyServer, authenticate


def _live_pole() -> PoLEState:
    g = LivenessGate()
    for _, (psl, psnl) in live_stream(40):
        g.update(p_s_given_live=psl, p_s_given_not_live=psnl)
    return g.state(sensor_digest=b"s", drand_round=b"\x00" * 8)


def run() -> None:
    # The person's Atlas authenticator + their YubiKey (step-up factor).
    user = build_identity_tree(os.urandom(32)).child("authorship")
    yubikey = YubiKeyBio()
    pole = _live_pole()

    # The bank registers the person's authenticator (public key only).
    bank = RelyingPartyServer("acme-bank")
    bank.register("customer-1", handle=user.handle, public=user.public, step_up_public=yubikey.public)
    print(f"[bank] registered customer-1 with acme-bank\n")

    # 1. LOGIN — routine, live presence only.
    ch = bank.challenge("customer-1", "login")
    a = authenticate(ch, authorship=user, pole=pole)
    print(f"1. login                -> {'APPROVED' if bank.verify('customer-1', a) else 'DENIED'}")

    # 2. HIGH-VALUE transfer — the bank demands a YubiKey step-up.
    ch2 = bank.challenge("customer-1", "authorize-transfer", require_step_up=True)
    a2 = authenticate(ch2, authorship=user, pole=pole, yubikey=yubikey, fingerprint_matched=True)
    print(f"2. transfer (step-up)   -> {'APPROVED' if bank.verify('customer-1', a2) else 'DENIED'}")

    # 3. RELAY ATTACK — an attacker relays the acme-bank proof to evil-bank.
    evil = RelyingPartyServer("evil-bank")
    evil.register("customer-1", handle=user.handle, public=user.public)
    ch3 = bank.challenge("customer-1", "login")
    a3 = authenticate(ch3, authorship=user, pole=pole)          # a genuine acme-bank proof
    print(f"3. relay to evil-bank   -> {'APPROVED (BAD!)' if evil.verify('customer-1', a3) else 'REJECTED (bound to acme-bank)'}")

    # 4. NO PRESENCE — dead liveness gate.
    dead = PoLEState(p_live=0.0, state_digest=b"d", drand_round=b"\x00" * 8, operate=False)
    ch4 = bank.challenge("customer-1", "login")
    try:
        authenticate(ch4, authorship=user, pole=dead)
        print("4. no presence          -> APPROVED (BAD!)")
    except AuthRefused as e:
        print(f"4. no presence          -> REFUSED ({e})")


if __name__ == "__main__":
    run()
