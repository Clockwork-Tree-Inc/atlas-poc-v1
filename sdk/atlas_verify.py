"""Atlas verify — a tiny, dependency-free Python client for the verified-human endpoint.

Drop this one file into your app; it uses only the standard library. See docs/VERIFY_QUICKSTART.md.

    from atlas_verify import is_live_human
    if is_live_human("https://node.clockwork-tree.com", token, min_tier=2):
        ...  # a live human, tier >= 2, verified offline by signature
"""
from __future__ import annotations

import json
import urllib.request
from typing import Any, Dict, Optional


def verify_presence(node_url: str, token: str, *, fmt: str = "vc", audience: Optional[str] = None,
                    min_tier: int = 1, public_key: Optional[str] = None, timeout: float = 10.0) -> Dict[str, Any]:
    """POST a presented Atlas credential to `/verify/presence` and return the verdict dict:
    {valid, verified_human, assurance_tier, epoch, subject}. `public_key` is optional — the node
    resolves the presenter from the token's DID if the persona registered (see /did/register)."""
    body: Dict[str, Any] = {"format": fmt, "token": token, "min_tier": min_tier}
    if audience is not None:
        body["audience"] = audience
    if public_key is not None:
        body["public_key"] = public_key
    req = urllib.request.Request(node_url.rstrip("/") + "/verify/presence",
                                 data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def is_live_human(node_url: str, token: str, *, min_tier: int = 1, **kw: Any) -> bool:
    """True iff the token proves a live human at assurance tier >= `min_tier`."""
    return bool(verify_presence(node_url, token, min_tier=min_tier, **kw).get("valid"))
