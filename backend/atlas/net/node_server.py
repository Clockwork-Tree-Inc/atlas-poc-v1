"""Atlas Mac node — a BLIND RELAY between the phones (+ an opt-in public verifier).

TWO paths, deliberately separate:

  1. BLIND RELAY (default for phone<->phone).  The two phones share an A-B key the
     Mac NEVER holds (A encapsulates to B's public key; the KEM shared secret is
     not recoverable from the relayed transcript). Messages and photos are sealed
     under the A-B key; the node only stores-and-forwards the OPAQUE blob to the
     recipient's mailbox. The node CANNOT read content — by construction. It sees
     only ENVELOPE METADATA (from/to mailbox, size, order).
     HONEST BOUNDARY: content is end-to-end; metadata (who<->whom, size, timing)
     is visible to the relay. Sealed-sender / mixing / cover-traffic is the
     upgrade path, not built here.

  2. PUBLIC VERIFIER/ANCHOR (opt-in).  For content you DELIBERATELY want publicly
     attributable ("library of truths"), a phone may submit a provenance bundle
     (+content) to be VERIFIED and ANCHORED. This path is public by choice and is
     never used for private A<->B traffic.

Run:  python -m atlas.net.node_server --host 0.0.0.0 --port 8787
Open: http://<mac-lan-ip>:8787/
"""

from __future__ import annotations

import base64
import html
import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..crypto import kem
from ..provenance import LedgerStub, PublicWitnessRegistry, verify_provenance
from .codec import bundle_from_json


def _lan_ip() -> str:
    """Best-effort LAN IP so the dashboard can tell the user where to point the
    phones — no terminal needed. Falls back to localhost."""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.168.255.255", 1))   # no packet sent; just picks the iface
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s)


@dataclass
class Envelope:
    seq: int
    frm: str
    to: str
    blob_b64: str          # OPAQUE A-B ciphertext — the node cannot open this
    size: int


@dataclass
class Mailbox:
    mid: str
    kem_pub: dict                                  # the phone's public key (for peers)
    inbox: List[Envelope] = field(default_factory=list)
    relayed_in: int = 0
    relayed_out: int = 0


@dataclass
class PublicRecord:
    seq: int
    content_hash_hex: str
    author_hex: str
    checks: Dict[str, str]
    accountable_built: bool


class AtlasNode:
    """Blind relay + opt-in public verifier. The relay holds NO A-B keys and never
    calls decrypt on relayed blobs."""

    _DEFERRABLE = {"live_provenance_ok", "verification_inherited_ok"}

    def __init__(self, port: int = 8787) -> None:
        self.port = port
        self._mailboxes: Dict[str, Mailbox] = {}
        self._seq = 0
        # opt-in public path only:
        self._ledger = LedgerStub()
        self._registry = PublicWitnessRegistry()
        self._public: List[PublicRecord] = []
        self._demo_log: List[str] = []
        self._demo_result: dict = {}
        # mock relying party (a "bank") the phone authenticates TO — Atlas as the
        # verified-human authenticator (NOT a bank/rail). Real banks consume this via
        # passkeys/WebAuthn; this is the demo endpoint.
        from ..auth import RelyingPartyServer
        self._rp = RelyingPartyServer("atlas-demo-bank")

    # -- relying party (auth demo) ------------------------------------------

    def rp_register(self, *, user_id: str, handle_b64: str, public: dict,
                    step_up_public_b64: str = "") -> dict:
        from ..auth.relying_party import _pub_obj
        self._rp.register(user_id, handle=base64.b64decode(handle_b64), public=_pub_obj(public),
                          step_up_public=base64.b64decode(step_up_public_b64) if step_up_public_b64 else None)
        return {"ok": True, "relying_party": self._rp.name}

    def rp_challenge(self, *, user_id: str, action: str, require_step_up: bool) -> dict:
        from ..auth import challenge_to_json
        return challenge_to_json(self._rp.challenge(user_id, action, require_step_up=require_step_up))

    def rp_verify(self, *, user_id: str, assertion: dict) -> dict:
        from ..auth import assertion_from_json
        ok = self._rp.verify(user_id, assertion_from_json(assertion))
        return {"approved": bool(ok)}

    # -- blind relay --------------------------------------------------------

    def register(self, *, mailbox: str, kem_pub: dict) -> dict:
        """A phone registers its mailbox + PUBLIC key so peers can encapsulate to
        it. The node learns only public material + the mailbox id (metadata)."""
        mb = self._mailboxes.get(mailbox) or Mailbox(mid=mailbox, kem_pub=kem_pub)
        mb.kem_pub = kem_pub
        self._mailboxes[mailbox] = mb
        return {"ok": True, "mailbox": mailbox}

    def peer_pubkey(self, mailbox: str) -> dict:
        mb = self._mailboxes.get(mailbox)
        if mb is None:
            raise KeyError(f"no such mailbox {mailbox!r}")
        return mb.kem_pub

    def relay_send(self, *, frm: str, to: str, blob_b64: str) -> dict:
        """Store an OPAQUE A-B-sealed blob in the recipient's inbox. The node does
        NOT (and cannot) open it — it holds no A-B key. Only metadata is recorded."""
        dst = self._mailboxes.get(to)
        if dst is None:
            raise KeyError(f"no such mailbox {to!r}")
        self._seq += 1
        env = Envelope(seq=self._seq, frm=frm, to=to, blob_b64=blob_b64,
                       size=len(_unb64(blob_b64)))
        dst.inbox.append(env)
        dst.relayed_in += 1
        src = self._mailboxes.get(frm)
        if src:
            src.relayed_out += 1
        return {"ok": True, "seq": self._seq}

    def relay_fetch(self, *, mailbox: str) -> dict:
        """Deliver + clear the recipient's pending opaque blobs. The recipient
        decrypts them locally with the A-B key (never on the node)."""
        mb = self._mailboxes.get(mailbox)
        if mb is None:
            raise KeyError(f"no such mailbox {mailbox!r}")
        out = [{"seq": e.seq, "frm": e.frm, "blob": e.blob_b64} for e in mb.inbox]
        mb.inbox.clear()
        return {"messages": out}

    # -- opt-in public verifier/anchor --------------------------------------

    def publish_provenance(self, *, bundle: dict, content_b64: str = "",
                           lk_hex_TESTONLY: str = "") -> dict:
        b = bundle_from_json(bundle)
        content = _unb64(content_b64) if content_b64 else b""
        self._ledger.anchor(b.content_hash)
        if lk_hex_TESTONLY:
            self._registry.publish(bytes.fromhex(lk_hex_TESTONLY), b.drand_round)
        v = verify_provenance(b, content=content, ledger=self._ledger,
                              witness_registry=self._registry)
        raw = {"integrity_ok": v.integrity_ok, "handle_ok": v.handle_ok,
               "signature_ok": v.signature_ok, "liveness_ok": v.liveness_ok,
               "anchored_ok": v.anchored_ok, "live_provenance_ok": v.live_provenance_ok,
               "verification_inherited_ok": v.verification_inherited_ok}
        labeled = {}
        for name, ok in raw.items():
            if not ok and name in self._DEFERRABLE and b.live_binding is None:
                labeled[name] = "deferred"
            else:
                labeled[name] = "ok" if ok else "fail"
        built = ["integrity_ok", "handle_ok", "signature_ok", "liveness_ok", "anchored_ok"]
        accountable = all(labeled[n] == "ok" for n in built)
        self._seq += 1
        self._public.append(PublicRecord(seq=self._seq, content_hash_hex=b.content_hash.hex(),
                                         author_hex=b.authorship_handle.hex(), checks=labeled,
                                         accountable_built=accountable))
        return {"ok": True, "accountable_built": accountable, "checks": labeled}

    # -- public witness anchor (holds PUBLIC halves only; no LK) -------------

    def register_witness_public(self, *, drand_round: bytes, pub) -> None:
        """A phone (LK holder) publishes ONLY the epoch witness PUBLIC half here so
        recipients can verify live-provenance WITHOUT the LK. Reveals nothing."""
        self._registry.register_public(drand_round, pub)

    def witness_public(self, drand_round: bytes):
        return self._registry.witness_pub(drand_round)

    # -- two-phone demo (in-process A<->B through the blind relay) -----------

    def record_demo(self, log, *, message: str, verdict: str) -> None:
        self._demo_log = list(log)
        self._demo_result = {"message": message, "verdict": verdict}

    def run_demo(self) -> dict:
        """Play Phone A + Phone B in-process through THIS node's blind relay. The
        node still only sees opaque blobs; the message/verdict shown are computed
        by the Phone-B client, not the server."""
        from .two_phone_demo import run as run_two_phone
        run_two_phone(self)
        return {"ok": True, "lines": self._demo_log}

    # -- HTTP ---------------------------------------------------------------

    def dispatch(self, method: str, path: str, body: dict):
        try:
            if method == "GET" and path in ("/", "/dashboard"):
                return 200, ("html", self.dashboard_html())
            if method == "GET" and path == "/status":
                return 200, ("json", self.status())
            if method == "POST" and path == "/relay/register":
                return 200, ("json", self.register(mailbox=body["mailbox"], kem_pub=body["kem_pub"]))
            if method == "GET" and path.startswith("/relay/pubkey/"):
                return 200, ("json", self.peer_pubkey(path.rsplit("/", 1)[-1]))
            if method == "POST" and path == "/relay/send":
                return 200, ("json", self.relay_send(frm=body["from"], to=body["to"], blob_b64=body["blob"]))
            if method == "GET" and path.startswith("/relay/fetch/"):
                return 200, ("json", self.relay_fetch(mailbox=path.rsplit("/", 1)[-1]))
            if method == "POST" and path == "/demo/run":
                self.run_demo()
                return 200, ("html", self.dashboard_html())   # land back on the dashboard
            if method == "POST" and path == "/rp/register":
                return 200, ("json", self.rp_register(
                    user_id=body["user_id"], handle_b64=body["handle"], public=body["public"],
                    step_up_public_b64=body.get("step_up_public", "")))
            if method == "POST" and path == "/rp/challenge":
                return 200, ("json", self.rp_challenge(
                    user_id=body["user_id"], action=body["action"],
                    require_step_up=bool(body.get("require_step_up", False))))
            if method == "POST" and path == "/rp/verify":
                return 200, ("json", self.rp_verify(user_id=body["user_id"], assertion=body["assertion"]))
            if method == "POST" and path == "/publish/provenance":
                return 200, ("json", self.publish_provenance(
                    bundle=body["bundle"], content_b64=body.get("content_b64", ""),
                    lk_hex_TESTONLY=body.get("lk_hex_TESTONLY", "")))
            return 404, ("json", {"error": "not found"})
        except KeyError as e:
            return 400, ("json", {"error": str(e)})
        except Exception as e:  # noqa: BLE001
            return 400, ("json", {"error": f"{type(e).__name__}: {e}"})

    # -- status + dashboard -------------------------------------------------

    def status(self) -> dict:
        return {
            "port": self.port,
            "mailboxes": [{"mid": m.mid, "pending": len(m.inbox),
                           "in": m.relayed_in, "out": m.relayed_out} for m in self._mailboxes.values()],
            "relayed_total": sum(m.relayed_in for m in self._mailboxes.values()),
            "public": [{"seq": r.seq, "content_hash": r.content_hash_hex[:16],
                        "author": r.author_hex[:16], "accountable_built": r.accountable_built,
                        "checks": r.checks} for r in self._public],
        }

    def dashboard_html(self) -> str:
        s = self.status()

        def chip(state):
            c = {"ok": "#1a7f37", "fail": "#cf222e", "deferred": "#9a6700"}.get(state, "#57606a")
            return f'<span style="color:{c};font-weight:600">{state}</span>'

        mb_rows = "".join(
            f"<tr><td><code>{html.escape(m['mid'])}</code></td><td>{m['pending']}</td>"
            f"<td>{m['in']}</td><td>{m['out']}</td></tr>" for m in s["mailboxes"]) or \
            "<tr><td colspan=4><em>no phones registered yet</em></td></tr>"

        pub_rows = ""
        for r in s["public"]:
            checks = " ".join(f"{html.escape(k.replace('_ok',''))}:{chip(v)}" for k, v in r["checks"].items())
            overall = chip("ok") if r["accountable_built"] else chip("fail")
            pub_rows += (f"<tr><td>{r['seq']}</td><td><code>{r['content_hash']}…</code></td>"
                         f"<td><code>{r['author']}…</code></td><td>{overall}</td>"
                         f"<td style='font-size:12px'>{checks}</td></tr>")
        pub_rows = pub_rows or "<tr><td colspan=5><em>nothing published to the public path</em></td></tr>"

        if self._demo_log:
            lines = "".join(f"<div>{html.escape(l)}</div>" for l in self._demo_log)
            demo_block = (
                '<div class=box style="border-color:#1a7f37">✅ <b>Demo ran.</b> Phone A &amp; Phone B ran '
                'inside this process to exercise the relay — the decryption/verification below was done by the '
                '<b>Phone-B client, NOT the server</b>. The server\'s own view (mailboxes) stayed opaque.'
                f'<div style="font:12px ui-monospace,monospace;margin-top:8px;line-height:1.6">{lines}</div></div>')
        else:
            demo_block = ""

        return f"""<!doctype html><html><head><meta charset=utf-8>
<meta http-equiv=refresh content=2><title>Atlas Mac Node</title>
<style>
 body{{font:14px -apple-system,system-ui,sans-serif;margin:24px;color:#1f2328;background:#fff}}
 h1{{font-size:20px}} h2{{font-size:15px;margin-top:28px;border-bottom:1px solid #d0d7de;padding-bottom:4px}}
 table{{border-collapse:collapse;width:100%;margin-top:8px}}
 td,th{{border:1px solid #d0d7de;padding:6px 8px;text-align:left}} th{{background:#f6f8fa}}
 code{{font:12px ui-monospace,monospace}}
 .pill{{display:inline-block;background:#ddf4ff;color:#0969da;border-radius:12px;padding:2px 10px;font-weight:600}}
 .box{{background:#f6f8fa;border:1px solid #d0d7de;border-radius:8px;padding:10px 14px;margin-top:8px}}
</style></head><body>
<h1>🛰️ Atlas Mac Node <span class=pill>{s['relayed_total']} blobs relayed (blind)</span></h1>
<div class=box>📱 <b>Point the phones here:</b> <code>http://{_lan_ip()}:{s.get('port', 8787)}</code>
&nbsp; (Mac &amp; phones on the same Wi-Fi). This node is running and listening.</div>
<div class=box>🔒 <b>Blind relay.</b> Phone↔phone messages are sealed under an A-B key the node
NEVER holds — the node stores &amp; forwards <b>opaque ciphertext it cannot read</b>. It sees only
envelope metadata (from/to mailbox, size, order). Content is end-to-end; metadata privacy
(sealed-sender / mixing) is a documented upgrade, not built here.</div>

<h2>Try it — two-phone end-to-end (no terminal)</h2>
<form method=post action=/demo/run style="margin:8px 0">
 <button type=submit style="font-size:14px;padding:8px 16px;border-radius:8px;border:1px solid #0969da;background:#0969da;color:#fff;font-weight:600;cursor:pointer">
 ▶ Run A→B demo</button>
 <span style="color:#57606a">— plays Phone A + Phone B through this blind relay (a message + a provenanced photo).</span>
</form>
{demo_block}

<h2>Mailboxes / relay (server is blind to content)</h2>
<table><tr><th>mailbox</th><th>pending</th><th>relayed in</th><th>relayed out</th></tr>{mb_rows}</table>

<h2>Public path (opt-in — content you CHOSE to make publicly attributable)</h2>
<table><tr><th>#</th><th>content hash</th><th>author</th><th>accountable*</th><th>checks</th></tr>{pub_rows}</table>
<p style="color:#57606a;font-size:12px">*over the checks this build produces (integrity·handle·signature·liveness·anchored);
live-provenance &amp; BBS+ inherited show <b>deferred</b> for phone bundles until the Swift pieces land.
This path is used ONLY for content you deliberately publish — never for private A↔B traffic.</p>
</body></html>"""


def serve(host: str = "0.0.0.0", port: int = 8787) -> None:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    node = AtlasNode(port=port)

    class Handler(BaseHTTPRequestHandler):
        def _reply(self, code, kind_obj):
            kind, obj = kind_obj
            blob = obj.encode() if kind == "html" else json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8" if kind == "html" else "application/json")
            self.send_header("Content-Length", str(len(blob)))
            self.end_headers()
            self.wfile.write(blob)

        def _body(self):
            n = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(n) or b"{}") if n else {}

        def do_GET(self):  # noqa: N802
            self._reply(*node.dispatch("GET", self.path, {}))

        def do_POST(self):  # noqa: N802
            self._reply(*node.dispatch("POST", self.path, self._body()))

        def log_message(self, *_):
            pass

    print(f"[atlas] Mac NODE (blind relay) on http://{host}:{port} — open http://<mac-lan-ip>:{port}/")
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Atlas Mac node — blind relay + opt-in public verifier")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8787)
    args = ap.parse_args()
    serve(args.host, args.port)
