"""Verified-human-as-a-service — the whole consumable flow in one runnable file.

    PHONE (the user's Atlas app)          RELYING PARTY (your app)
    ─────────────────────────────         ────────────────────────
    mints a presence credential   ──────▶ POST /verify/presence
    (VC or OIDC id_token)                  ◀── {valid, verified_human, assurance_tier, ...}

Run in-process (no server):
    python -m demos.demo_verify_service
Run against a live node over HTTP:
    python -m demos.demo_verify_service --node https://node.clockwork-tree.com

What an integrator writes is only the RIGHT column — see docs/VERIFY_QUICKSTART.md.
"""
from __future__ import annotations

import argparse
import base64
import json

from atlas.attestation.presence_attestation import AssuranceTier, attest
from atlas.crypto.sign import keypair_from_seed
from atlas.interop.presence_interop import as_oidc, as_vc


# --------------------------------------------------------------------------- PHONE side (Atlas app)
def mint_credential(*, fmt: str, subject: str, audience: str = "your-app", nonce: str = "n-1"):
    """What the user's phone does: prove live presence at a drand round + tier, emit it as a standard
    credential. (Here a deterministic demo persona + a fixed round; on device these are real.)"""
    phone = keypair_from_seed(bytes([7]) * 32)
    att = attest(phone, beacon_round=910231, beacon_sig=b"the-drand-round-signature",
                 tier=AssuranceTier.WEARABLE, presentation_binding=b"\x11" * 32)
    token = (as_oidc(phone, att, subject=subject, audience=audience, nonce=nonce)
             if fmt == "oidc" else as_vc(phone, att, subject=subject))
    public_key_b64 = base64.b64encode(phone.public.encode()).decode()
    return token, public_key_b64


# --------------------------------------------------------------------------- RELYING PARTY side
def verify_locally(*, fmt: str, token: str, public_key_b64: str, audience=None, min_tier=1) -> dict:
    from atlas.net.node_server import AtlasNode
    return AtlasNode().verify_presence(credential_format=fmt, token=token,
                                       public_key_b64=public_key_b64, audience=audience, min_tier=min_tier)


def verify_over_http(node: str, *, fmt: str, token: str, public_key_b64: str, audience=None, min_tier=1) -> dict:
    import urllib.request
    body = json.dumps({"format": fmt, "token": token, "public_key": public_key_b64,
                       "audience": audience, "min_tier": min_tier}).encode()
    req = urllib.request.Request(node.rstrip("/") + "/verify/presence", data=body,
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--node", help="verifier base URL (omit to verify in-process)")
    ap.add_argument("--format", choices=["vc", "oidc"], default="vc")
    ap.add_argument("--min-tier", type=int, default=1)
    args = ap.parse_args()

    token, pk = mint_credential(fmt=args.format, subject="alice-persona", audience="your-app")
    print(f"[phone] minted a {args.format} verified-human credential ({len(token)} chars)")

    audience = "your-app" if args.format == "oidc" else None
    if args.node:
        print(f"[app]   POST {args.node}/verify/presence")
        result = verify_over_http(args.node, fmt=args.format, token=token, public_key_b64=pk,
                                  audience=audience, min_tier=args.min_tier)
    else:
        print("[app]   verify in-process (AtlasNode.verify_presence)")
        result = verify_locally(fmt=args.format, token=token, public_key_b64=pk,
                                audience=audience, min_tier=args.min_tier)

    print("[app]   verdict:", json.dumps(result))
    ok = bool(result.get("valid"))
    print(f"\n=> {'ACCEPT' if ok else 'REJECT'} — "
          f"{'a live human, tier ' + str(result.get('assurance_tier')) + ', verified offline by signature' if ok else 'not a valid live-human presentation'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
