"""Atlas as the verified-human AUTHENTICATOR — for the bank and everything else.

Atlas is NOT a bank / wallet / payment rail. It authenticates a PERSON to a relying
party (a bank, a service, a site): it proves "a verified, live, present human —
optionally with a deliberate hardware step-up — authorized THIS specific action", and
hands that proof to whoever runs the actual system. Passkey/WebAuthn-shaped, but far
stronger: liveness + presence + optional YubiKey, bound to the relying party's
challenge.

  * REGISTER — the user enrols an authenticator public key (their authorship
    pseudonym) with the relying party (like a WebAuthn credential).
  * AUTHENTICATE — the RP issues a challenge for an action; Atlas returns a signed
    assertion bound to (relying_party, action, challenge), gated by LIVE PRESENCE and,
    for high-assurance actions, a YubiKey fingerprint STEP-UP. The RP verifies the
    assertion against the registered key(s). Atlas never sees RP secrets; the RP never
    gets Atlas keys.

Phishing/relay-resistant: the assertion binds the RELYING PARTY, so a proof made for
one site cannot be replayed to another. Fail-closed: no presence, or a required
step-up without the YubiKey fingerprint, yields no assertion.

The hardware CARDS are a future EXTRA-STRENGTH factor for the shipped product (another
separate-device assurance, like the YubiKey); the USB is recovery-only. Higher
identity assurance ("a verified REAL human is behind this pseudonym", without
revealing who) composes the existing Real-ID inherited proof (realid/), unchanged.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Dict, Optional

from ..crypto.primitives import H, random_bytes
from ..crypto.sign import HybridSigPublic, sign, verify
from ..keys.hardware_key import HighStakesRequest, YubiKeyBio, verify_high_stakes
from ..keys.identity import Child, handle_of
from ..liveness.bayes import PoLEState


class AuthRefused(Exception):
    """No assertion issued — no live presence, or a required YubiKey step-up was
    absent (fail-closed)."""


@dataclass(frozen=True)
class AuthChallenge:
    """What the relying party sends. `challenge` is a fresh RP nonce (anti-replay);
    `require_step_up` demands the YubiKey for a high-assurance action."""

    relying_party: str        # e.g. "acme-bank"
    action: str               # "login" | "authorize-transfer" | "confirm-18+" | ...
    challenge: bytes          # fresh RP nonce
    require_step_up: bool = False

    def binding(self) -> bytes:
        return H(b"atlas/auth/challenge", self.relying_party.encode(), self.action.encode(),
                 self.challenge, b"\x01" if self.require_step_up else b"\x00")


@dataclass
class VerifiedHumanAssertion:
    """Atlas's response: bound to the RP challenge, signed by the authorship
    authenticator, gated live, optionally YubiKey-stepped-up."""

    relying_party: str
    action: str
    challenge: bytes
    authorship_handle: bytes
    authorship_public: HybridSigPublic
    live: bool
    stepped_up: bool
    signature: bytes = b""
    step_up_public: Optional[bytes] = None
    step_up_signature: Optional[bytes] = None

    def core(self) -> bytes:
        return H(b"atlas/auth/assertion", self.relying_party.encode(), self.action.encode(),
                 self.challenge, self.authorship_handle,
                 b"\x01" if self.live else b"\x00",
                 b"\x01" if self.stepped_up else b"\x00")


def authenticate(challenge: AuthChallenge, *, authorship: Child, pole: PoLEState,
                 yubikey: Optional[YubiKeyBio] = None,
                 fingerprint_matched: bool = False) -> VerifiedHumanAssertion:
    """Produce a verified-human assertion for the RP's challenge. Requires live
    presence; for a step-up challenge, requires a YubiKey fingerprint authorization
    (raises if absent — fail-closed)."""
    if not pole.operate:
        raise AuthRefused("no live presence")

    stepped_up = False
    su_pub: Optional[bytes] = None
    su_sig: Optional[bytes] = None
    if challenge.require_step_up:
        if yubikey is None:
            raise AuthRefused("relying party requires a YubiKey step-up")
        req = HighStakesRequest(action="auth:" + challenge.action, context=challenge.binding(),
                                challenge=challenge.challenge)
        su_sig = yubikey.authorize(req, fingerprint_matched=fingerprint_matched)  # raises FingerprintRequired
        su_pub = yubikey.public
        stepped_up = True

    assertion = VerifiedHumanAssertion(
        relying_party=challenge.relying_party, action=challenge.action, challenge=challenge.challenge,
        authorship_handle=authorship.handle, authorship_public=authorship.public,
        live=True, stepped_up=stepped_up, step_up_public=su_pub, step_up_signature=su_sig)
    assertion.signature = sign(authorship.keypair, assertion.core())
    return assertion


def verify_assertion(assertion: VerifiedHumanAssertion, challenge: AuthChallenge, *,
                     registered_handle: bytes, registered_public: HybridSigPublic,
                     registered_step_up_public: Optional[bytes] = None) -> bool:
    """Relying-party side. The assertion must be by the REGISTERED authenticator, over
    THIS exact challenge (incl. this relying party — relay-resistant), from a live
    human, and — if the RP required a step-up — carry a valid YubiKey authorization by
    the REGISTERED YubiKey. Any mismatch -> False (fail-closed)."""
    # 1. bound to THIS challenge / action / relying party (no replay, no relay to another RP)
    if (assertion.relying_party != challenge.relying_party
            or assertion.action != challenge.action
            or assertion.challenge != challenge.challenge):
        return False
    # 2. the registered authenticator (like a WebAuthn credential), consistent handle/public
    if assertion.authorship_handle != registered_handle:
        return False
    if handle_of(assertion.authorship_public.encode()) != assertion.authorship_handle:
        return False
    if assertion.authorship_public.encode() != registered_public.encode():
        return False
    # 3. live human, signed by that authenticator
    if not assertion.live:
        return False
    if not verify(assertion.authorship_public, assertion.core(), assertion.signature):
        return False
    # 4. high-assurance step-up: a valid authorization by the REGISTERED YubiKey
    if challenge.require_step_up:
        if not assertion.stepped_up or assertion.step_up_public is None or assertion.step_up_signature is None:
            return False
        if registered_step_up_public is None or assertion.step_up_public != registered_step_up_public:
            return False  # attacker's own YubiKey cannot stand in for the registered one
        req = HighStakesRequest(action="auth:" + challenge.action, context=challenge.binding(),
                                challenge=challenge.challenge)
        if not verify_high_stakes(assertion.step_up_public, req, assertion.step_up_signature):
            return False
    return True


# -- wire serialization (assertions cross the network to the relying party) ----

def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _pub_json(p: HybridSigPublic) -> dict:
    return {"mldsa_pk": _b64(p.mldsa_pk), "ed_pk": _b64(p.ed_pk)}


def _pub_obj(d: dict) -> HybridSigPublic:
    return HybridSigPublic(mldsa_pk=base64.b64decode(d["mldsa_pk"]), ed_pk=base64.b64decode(d["ed_pk"]))


def assertion_to_json(a: VerifiedHumanAssertion) -> dict:
    return {
        "relying_party": a.relying_party, "action": a.action,
        "challenge": _b64(a.challenge), "authorship_handle": _b64(a.authorship_handle),
        "authorship_public": _pub_json(a.authorship_public),
        "live": a.live, "stepped_up": a.stepped_up, "signature": _b64(a.signature),
        "step_up_public": _b64(a.step_up_public) if a.step_up_public else None,
        "step_up_signature": _b64(a.step_up_signature) if a.step_up_signature else None,
    }


def assertion_from_json(o: dict) -> VerifiedHumanAssertion:
    return VerifiedHumanAssertion(
        relying_party=o["relying_party"], action=o["action"],
        challenge=base64.b64decode(o["challenge"]),
        authorship_handle=base64.b64decode(o["authorship_handle"]),
        authorship_public=_pub_obj(o["authorship_public"]),
        live=o["live"], stepped_up=o["stepped_up"],
        signature=base64.b64decode(o["signature"]),
        step_up_public=base64.b64decode(o["step_up_public"]) if o.get("step_up_public") else None,
        step_up_signature=base64.b64decode(o["step_up_signature"]) if o.get("step_up_signature") else None,
    )


# -- the mock relying party (a "bank") — the SERVER the phone authenticates to --

@dataclass
class Registration:
    handle: bytes
    public: HybridSigPublic
    step_up_public: Optional[bytes] = None


class RelyingPartyServer:
    """A relying party (e.g. a bank). Registers authenticators, issues one-shot
    challenges, and verifies assertions. Atlas (the phone) authenticates TO this; it
    never holds Atlas's keys. Challenges are single-use (consumed on verify), so a
    captured assertion cannot be replayed."""

    def __init__(self, name: str):
        self.name = name
        self._users: Dict[str, Registration] = {}
        self._open: Dict[str, AuthChallenge] = {}

    def register(self, user_id: str, *, handle: bytes, public: HybridSigPublic,
                 step_up_public: Optional[bytes] = None) -> None:
        self._users[user_id] = Registration(handle=handle, public=public, step_up_public=step_up_public)

    def challenge(self, user_id: str, action: str, *, require_step_up: bool = False) -> AuthChallenge:
        ch = AuthChallenge(relying_party=self.name, action=action,
                           challenge=random_bytes(16), require_step_up=require_step_up)
        self._open[ch.challenge.hex()] = ch
        return ch

    def verify(self, user_id: str, assertion: VerifiedHumanAssertion) -> bool:
        reg = self._users.get(user_id)
        if reg is None:
            return False
        ch = self._open.pop(assertion.challenge.hex(), None)   # consume: one-shot, no replay
        if ch is None:
            return False                                       # unknown / already-used / relayed challenge
        return verify_assertion(assertion, ch, registered_handle=reg.handle,
                                registered_public=reg.public,
                                registered_step_up_public=reg.step_up_public)


def challenge_to_json(ch: AuthChallenge) -> dict:
    return {"relying_party": ch.relying_party, "action": ch.action,
            "challenge": _b64(ch.challenge), "require_step_up": ch.require_step_up}


def challenge_from_json(o: dict) -> AuthChallenge:
    return AuthChallenge(relying_party=o["relying_party"], action=o["action"],
                         challenge=base64.b64decode(o["challenge"]),
                         require_step_up=bool(o.get("require_step_up", False)))
