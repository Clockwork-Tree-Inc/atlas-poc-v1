"""APNs push — a content-free 'you have mail' wake, nothing more.

Privacy model: the node stores a mailbox -> device-token map and, when a sealed blob lands in a
mailbox, sends a SILENT (content-available) push carrying NO payload — no content, no sender, not
even "a message". Apple's servers see only a token + a wake. The app wakes in the background,
fetches the sealed blob from its mailbox, decrypts locally, and posts a GENERIC local
notification. The push is a doorbell with no note attached.

Credentials come from the environment (never in the repo):
  ATLAS_APNS_KEY_PATH  — path to the AuthKey_XXXX.p8 from the Apple developer portal
  ATLAS_APNS_KEY_ID    — the key's 10-char Key ID
  ATLAS_APNS_TEAM_ID   — your 10-char Team ID
  ATLAS_APNS_BUNDLE_ID — the app bundle id (apns-topic)
  ATLAS_APNS_ENV       — 'sandbox' (default, dev builds) or 'production'

Until a .p8 key is present the registry still works; send() is a no-op that reports 'unconfigured'
(the pipeline is inert, not broken).
"""

from __future__ import annotations

import json
import os
import time
from typing import Dict, Optional


def _apns_host() -> str:
    env = os.environ.get("ATLAS_APNS_ENV", "sandbox")
    return "api.push.apple.com" if env == "production" else "api.sandbox.push.apple.com"


class PushRegistry:
    """mailbox-id -> APNs device token, persisted append-only to the node storage dir."""

    def __init__(self) -> None:
        store = os.environ.get("ATLAS_STORAGE", "/var/lib/atlas")
        try:
            os.makedirs(store, exist_ok=True)
            self._path = os.path.join(store, "push_tokens.json")
        except OSError:
            self._path = "atlas-push_tokens.json"
        self._tokens: Dict[str, str] = {}
        try:
            with open(self._path) as fh:
                self._tokens = json.load(fh)
        except (OSError, ValueError):
            self._tokens = {}

    def register(self, mailbox: str, token: str) -> None:
        self._tokens[mailbox] = token
        try:
            with open(self._path, "w") as fh:
                json.dump(self._tokens, fh)
        except OSError:
            pass

    def token_for(self, mailbox: str) -> Optional[str]:
        return self._tokens.get(mailbox)


def _auth_jwt() -> Optional[str]:
    """ES256 JWT signed with the APNs .p8 key. Cached ~50 min (APNs allows <60)."""
    key_path = os.environ.get("ATLAS_APNS_KEY_PATH")
    key_id = os.environ.get("ATLAS_APNS_KEY_ID")
    team_id = os.environ.get("ATLAS_APNS_TEAM_ID")
    if not (key_path and key_id and team_id and os.path.exists(key_path)):
        return None
    now = int(time.time())
    cached = _auth_jwt._cache  # type: ignore[attr-defined]
    if cached and now - cached[0] < 3000:
        return cached[1]
    try:
        import jwt  # PyJWT
        with open(key_path) as fh:
            key = fh.read()
        tok = jwt.encode({"iss": team_id, "iat": now}, key,
                         algorithm="ES256", headers={"kid": key_id})
        _auth_jwt._cache = (now, tok)  # type: ignore[attr-defined]
        return tok
    except Exception:
        return None


_auth_jwt._cache = None  # type: ignore[attr-defined]


def send_wake(mailbox: str, registry: PushRegistry) -> dict:
    """Silent, content-free background wake to the mailbox's device (if any). Best-effort."""
    token = registry.token_for(mailbox)
    if not token:
        return {"pushed": False, "reason": "no-token"}
    jwt_tok = _auth_jwt()
    bundle = os.environ.get("ATLAS_APNS_BUNDLE_ID")
    if not (jwt_tok and bundle):
        return {"pushed": False, "reason": "unconfigured"}   # inert until a .p8 key is installed
    try:
        import httpx
        headers = {
            "authorization": f"bearer {jwt_tok}",
            "apns-topic": bundle,
            "apns-push-type": "background",
            "apns-priority": "5",
        }
        # content-available:1 with NO alert/sound/body => silent wake, zero content.
        body = {"aps": {"content-available": 1}}
        with httpx.Client(http2=True, timeout=8) as client:
            r = client.post(f"https://{_apns_host()}/3/device/{token}",
                            headers=headers, content=json.dumps(body))
        return {"pushed": r.status_code == 200, "status": r.status_code}
    except Exception as e:  # never raise into the relay path
        return {"pushed": False, "reason": str(e)}
