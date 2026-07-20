"""Mac backend node — the PQC tunnel endpoint the iPhone talks to (PoC).

The phone (`ios/AtlasApp/Session/AtlasTunnelClient.swift`) performs the REAL hybrid
KEM handshake (ML-KEM-768 + X25519, X-Wing combiner) and AES-256-GCM tunnel; this
is the matching server half. Endpoints:

  GET  /kem/public-key      -> {"mlkemEK": b64, "x25519PK": b64}
  POST /kem/complete        {"mlkemCT": b64, "x25519EphPK": b64} -> {"session": hex}
  POST /tunnel/message      {"session": hex, "ciphertext": b64, "mode": "1"|"2"}
                            -> {"ciphertext": b64, "mode": "1"}   (sealed ACK)

The crypto is real and cross-impl: the phone's derived `shared` must equal this
server's `decapsulate(...)`, which is exactly the Swift<->Python KEM interop the
X-Wing combiner parity vector now pins statically (`xwing_combine`). If the tunnel
opens on device, ML-KEM interop is confirmed end-to-end.

`TunnelBackend` is pure logic (unit-testable in-process); `serve()` is a thin
stdlib http.server wrapper so the Mac can run it with no dependencies:
    python -m atlas.net.tunnel_backend --host 0.0.0.0 --port 8787
"""

from __future__ import annotations

import base64
import json
import os
from typing import Dict, Tuple

from ..crypto import kem
from ..session.tunnel import Message, SendMode, open_message, seal


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s)


class TunnelBackend:
    """PQC tunnel server logic. Holds one hybrid-KEM keypair and a map of live
    session tunnel keys derived from each phone's encapsulation."""

    def __init__(self) -> None:
        self._kp = kem.generate_keypair()
        self._sessions: Dict[str, bytes] = {}

    # -- handshake ----------------------------------------------------------

    def public_key(self) -> dict:
        """The server's hybrid-KEM public half the phone encapsulates to."""
        pub = self._kp.public
        return {"mlkemEK": _b64(pub.mlkem_ek), "x25519PK": _b64(pub.x25519_pk)}

    def complete(self, *, mlkem_ct: bytes, x25519_eph_pk: bytes) -> str:
        """Decapsulate the phone's ciphertext to the SAME shared secret the phone
        derived, and open a session. Returns the session id."""
        shared = kem.decapsulate(self._kp, mlkem_ct, x25519_eph_pk)
        session = os.urandom(16).hex()
        self._sessions[session] = shared
        return session

    # -- messaging ----------------------------------------------------------

    def handle_message(self, *, session: str, ciphertext: bytes, mode: int) -> dict:
        """Open a sealed message under the session tunnel key and return a sealed
        acknowledgement (bidirectional proof the tunnel works)."""
        key = self._sessions.get(session)
        if key is None:
            raise KeyError("unknown session (handshake first)")
        # NORMAL mode carries the full nonce||ct||tag blob in `ciphertext`.
        msg = Message(mode=SendMode(mode), ciphertext=ciphertext)
        plaintext = open_message(msg, key=key)
        ack = seal(b"ATLAS-ACK:" + plaintext, mode=SendMode.NORMAL, key=key)
        return {"ciphertext": _b64(ack.ciphertext), "mode": str(ack.mode.value)}

    # -- JSON adapters (used by the HTTP wrapper) ---------------------------

    def dispatch(self, method: str, path: str, body: dict) -> Tuple[int, dict]:
        try:
            if method == "GET" and path == "/kem/public-key":
                return 200, self.public_key()
            if method == "POST" and path == "/kem/complete":
                session = self.complete(mlkem_ct=_unb64(body["mlkemCT"]),
                                        x25519_eph_pk=_unb64(body["x25519EphPK"]))
                return 200, {"session": session}
            if method == "POST" and path == "/tunnel/message":
                out = self.handle_message(session=body["session"],
                                          ciphertext=_unb64(body["ciphertext"]),
                                          mode=int(body["mode"]))
                return 200, out
            return 404, {"error": "not found"}
        except KeyError as e:
            return 400, {"error": str(e)}
        except Exception as e:  # noqa: BLE001 — PoC: surface the failure to the client
            return 400, {"error": f"{type(e).__name__}: {e}"}


def serve(host: str = "0.0.0.0", port: int = 8787) -> None:
    """Run the backend over stdlib HTTP (no third-party deps). Point the phone's
    AtlasTunnelClient(baseURL:) at http://<mac-lan-ip>:<port>."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    backend = TunnelBackend()

    class Handler(BaseHTTPRequestHandler):
        def _send(self, code: int, obj: dict) -> None:
            blob = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(blob)))
            self.end_headers()
            self.wfile.write(blob)

        def _body(self) -> dict:
            n = int(self.headers.get("Content-Length", 0))
            if n == 0:
                return {}
            return json.loads(self.rfile.read(n) or b"{}")

        def do_GET(self):  # noqa: N802
            code, obj = backend.dispatch("GET", self.path, {})
            self._send(code, obj)

        def do_POST(self):  # noqa: N802
            code, obj = backend.dispatch("POST", self.path, self._body())
            self._send(code, obj)

        def log_message(self, *_args):  # quiet
            pass

    print(f"[atlas] PQC tunnel backend on http://{host}:{port}  (Ctrl-C to stop)")
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Atlas PQC tunnel backend (Mac node)")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8787)
    args = ap.parse_args()
    serve(args.host, args.port)
