# Verify a live human — 15-minute quickstart

Atlas turns **"a verified, unique, living human is present right now"** into a claim your app can
consume through protocols you already speak — a Verifiable Credential or an OpenID Connect ID token —
and **verify offline, by signature.** No SDK lock-in, no per-login callback to us, no way for anyone
(including us) to correlate your users across apps.

You integrate the **relying-party (RP) side** only. The user's Atlas app produces the credential; you
check it.

---

## 1. The endpoint

```
POST /verify/presence
Content-Type: application/json
```

**Request**

| field        | required | meaning                                             |
|--------------|----------|-----------------------------------------------------|
| `format`     | yes      | `"vc"` (Verifiable Credential) or `"oidc"` (ID token) |
| `token`      | yes      | the credential the user's Atlas app presented       |
| `public_key` | yes      | the presenter's public key (base64) — see §4        |
| `audience`   | oidc     | your app's audience id (OIDC only)                  |
| `min_tier`   | no       | minimum assurance tier to accept (default `1`)      |

**Response**

```json
{ "valid": true, "verified_human": true, "assurance_tier": 2, "epoch": "3e7", "subject": "persona-01" }
```

- `valid` — `verified_human` **and** `assurance_tier ≥ min_tier`. This is the one bit you gate on.
- `assurance_tier` — **1** = AMBIENT (phone sensors), **2** = WEARABLE (on-body secure element). Pick
  your `min_tier` for the risk: a comment box is fine at 1; moving money wants 2.
- `epoch` — the drand round the presence held at (freshness; un-pre-makeable).
- `subject` — the persona id **for your app**. It does **not** link to the same human in another app.

---

## 2. curl it

```bash
curl -s -X POST https://node.clockwork-tree.com/verify/presence \
  -H 'Content-Type: application/json' \
  -d '{"format":"vc","token":"<the credential>","public_key":"<b64>","min_tier":2}'
```

## 3. Run the reference client

```bash
# in-process (no server):
python -m demos.demo_verify_service
# against a live verifier:
python -m demos.demo_verify_service --node https://node.clockwork-tree.com --format oidc --min-tier 2
```

`demos/demo_verify_service.py` shows both sides — the phone minting a credential and your app
verifying it. In production you write only the verify call.

---

## 4. Where the credential and key come from

You already have a moment where the user authenticates — a passkey / WebAuthn or an OIDC sign-in.
Atlas rides **that** seam: the presented credential arrives through your existing flow, and you
forward it to `/verify/presence`.

**You usually don't pass `public_key` at all.** When the persona registered its key
(`POST /did/register {public_key}`, an enrolment step done once), the verifier **resolves** the
presenter from the token's DID (`kid` / `iss`). So your call is just `{format, token, min_tier}`.
Pass `public_key` only for an unregistered, self-certifying presentation.

## 5. Drop-in SDK

Two dependency-free files in `sdk/` — no build step:

```python
# Python (stdlib only)
from atlas_verify import is_live_human
ok = is_live_human("https://node.clockwork-tree.com", token, min_tier=2)
```
```js
// JavaScript (Node 18+ / browser fetch)
import { isLiveHuman } from "./atlas-verify.js";
const ok = await isLiveHuman("https://node.clockwork-tree.com", token, { minTier: 2 });
```

## 6. The deal (offline means trust is contractual, not technical)

Because verification is **offline and un-loggable by us**, the guarantees that protect the user are a
**relying-party agreement**, not a server we run:

- **Don't retain** the presentation beyond the session.
- **Don't attempt to correlate** a persona across apps or link it to a legal identity — you can't
  from the token, and you agree not to try by side channel.
- Treat `assurance_tier` honestly; don't claim more assurance than the tier states.

That's the whole integration: **one POST, one bit to gate on** — and a login a stolen device, a bot,
or a coerced session can't pass.
