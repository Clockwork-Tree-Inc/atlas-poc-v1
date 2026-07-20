# Handoff — Atlas as the verified-human authenticator (device wiring)

Atlas authenticates a PERSON to a relying party (a bank, a service, anything) — it is
NOT a bank/wallet/rail. The reference + Swift parity are built and green
(`auth/relying_party.py`, `Auth/RelyingParty.swift`, 302 tests). Two device tracks:
a **demo path** (show it working now, phone ↔ Mac) and the **real path** (how existing
banks consume it — passkeys).

## The reference, recap

`AuthChallenge (relying_party, action, challenge, require_step_up)` → `authenticate`
(live presence; YubiKey fingerprint step-up for high-assurance) → `VerifiedHumanAssertion`
→ `verify_assertion`. Relay-resistant (bound to the relying party), fail-closed. See the
in-process demo: `python -m atlas.auth.demo` (login ✓, step-up ✓, relay REJECTED,
no-presence REFUSED).

---

## Track A — demo it now (phone authenticates to the Mac "bank")

The node exposes a mock relying party (`atlas-demo-bank`): `POST /rp/register`,
`POST /rp/challenge`, `POST /rp/verify`.

App side (an **Auth** tab, mirroring the Messaging tab):
1. Build the enrolled authorship `Child` + a `YubiKeyBio` (model, or the real YubiKey
   via YubiKit).
2. `POST /rp/register` with `{user_id, handle (b64), public (mldsa_pk/ed_pk b64), step_up_public (b64)}`.
3. For an action: `POST /rp/challenge {user_id, action, require_step_up}` → decode the
   `AuthChallenge`.
4. `let a = try authenticate(challenge, authorship: child, pole: livePoLE, yubikey: yk,
   fingerprintMatched: …)`.
5. `POST /rp/verify {user_id, assertion: <assertion JSON>}` → show **APPROVED / DENIED**.
6. Demo the relay-rejection: register the same user with a *second* mock RP name and show
   an acme-bank proof is rejected there.

Assertion/challenge JSON shapes match the Python (`assertion_to_json`,
`challenge_to_json`) so the wire is portable.

---

## Track B — the REAL path: Atlas as a passkey provider (how existing banks use it)

You **cannot** replace the Face ID inside another app (`LocalAuthentication` is
Apple-locked). But the modern, cross-app "Face-ID-like" method banks adopt is
**passkeys / WebAuthn**, and **iOS 17+ lets a third-party app be the passkey/credential
provider**. That is the path where an *existing* passkey-supporting bank uses Atlas with
**no bank code change**.

Steps (bigger, but this is the product):
1. **ASCredentialProviderExtension** — add a Credential Provider app extension so Atlas
   registers as a passkey provider (`ASAuthorizationSecurityKeyPublicKeyCredentialProvider`
   / passkey provider APIs, `com.apple.developer.authentication-services.credential-provider`
   entitlement).
2. **Map our assertion to WebAuthn.** WebAuthn's `authenticatorData` + `clientDataJSON` +
   signature is our `VerifiedHumanAssertion` in the ecosystem's format: the RP challenge
   → `clientDataJSON`; sign with the credential key **after** our gate (live presence +
   YubiKey step-up). The relying-party binding we already enforce is exactly WebAuthn's
   RP-ID origin binding (phishing resistance) — keep it.
3. **Gate before signing.** The passkey signature is only produced once `authenticate`'s
   gate passes (live presence, and the YubiKey fingerprint for high-value). That is the
   whole value: to the bank it's a standard passkey; underneath it's liveness + presence
   + hardware.
4. **Honest boundary:** the bank must support passkeys/WebAuthn (growing fast) and the
   user selects Atlas as their provider. Banks without passkeys need an SDK integration
   (their choice) — you cannot override them unilaterally.

**Report:** Track A working phone↔Mac (approved / step-up / relay-rejected), and a spike
on the Credential Provider extension (does iOS offer Atlas as a passkey provider for a
WebAuthn test site?).

---

## Payments, in this frame

A payment is just an **action** — `authorize-transfer` with `require_step_up=True`. No
separate system. The air-gapped CARD is a future extra-strength signer, not needed now;
the USB is recovery-only.
