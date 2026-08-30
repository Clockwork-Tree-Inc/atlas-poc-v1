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
from ..keys.identity import Profile
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


def mailbox_for(profile: Profile) -> str:
    """Relay MAILBOX address for a persona = hex of its messaging-feature handle.

    OPAQUE and per-persona: two personas of the same human get UNLINKABLE mailboxes,
    it reveals no human-readable identity, and it is stable per persona so peers can
    address it (within-persona addressable, cross-persona unlinkable). This replaces
    human-chosen strings like "alice"/"bob", which were a stable, linkable identifier.
    (Hiding the SENDER of a relayed envelope is the separate sealed-sender upgrade.)"""
    return profile.feature("messaging").handle.hex()


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

    def __init__(self, port: int = 8787, *, epoch_service=None) -> None:
        self.port = port
        # The LKG aggregator + epoch beacon is TRUSTED Atlas infrastructure and lives on Atlas's own
        # servers (`beacon.epoch_service.EpochBeaconService`), NOT on this blind relay. The relay only
        # CONSUMES + VERIFIES signed epoch rounds. `epoch_service` is that source: in production an
        # authenticated client to the remote Atlas epoch service (pinned aggregator key); in a
        # single-process PoC an in-process `EpochBeaconService`. If None, this bare relay has no epoch
        # source yet and honestly falls back to the drand BOOTSTRAP at /beacon.
        self._epoch_service = epoch_service
        self._mailboxes: Dict[str, Mailbox] = {}
        self._did_registry: Dict[str, Any] = {}   # kid / did:atlas:kid / did:cid -> HybridSigPublic
        self._seq = 0
        # opt-in public path only:
        self._ledger = LedgerStub()
        self._registry = PublicWitnessRegistry()
        self._public: List[PublicRecord] = []
        self._demo_log: List[str] = []
        self._demo_result: dict = {}
        from .push import PushRegistry
        self._push = PushRegistry()
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

    def relay_send(self, *, to: str, blob_b64: str, frm: str = "") -> dict:
        """Store an OPAQUE A-B-sealed blob in the recipient's inbox. SEALED SENDER: the sender rides
        INSIDE the sealed blob, so the relay routes on `to` alone and learns nothing about who sent.
        `frm` is accepted for backward-compat but is NEVER stored and NEVER counted — the node keeps
        no per-sender metadata. The node cannot open the blob (it holds no A-B key)."""
        dst = self._mailboxes.get(to)
        if dst is None:
            # Auto-create on first delivery: a ROTATING mailbox is DERIVED, never pre-registered, so
            # the box must spring into existence on use (matches the reference MailboxRelay and is
            # what enables #43 rotation). Holds no kem_pub — it is purely a delivery target.
            dst = Mailbox(mid=to, kem_pub={})
            self._mailboxes[to] = dst
        self._seq += 1
        # frm is discarded — the envelope records NO sender (sealed-sender). Only the recipient
        # mailbox, size, and order are visible, which is inherent to any store-and-forward relay.
        env = Envelope(seq=self._seq, frm="", to=to, blob_b64=blob_b64, size=len(_unb64(blob_b64)))
        dst.inbox.append(env)
        dst.relayed_in += 1                         # the recipient's own inbox count (no sender info)
        # Ring the recipient's doorbell: a SILENT, content-free wake (no content, no sender).
        # Best-effort — never blocks or fails the relay.
        from .push import send_wake
        push = send_wake(to, self._push)
        return {"ok": True, "seq": self._seq, "push": push.get("pushed", False)}

    def push_register(self, *, mailbox: str, token: str) -> dict:
        """Bind a device's APNs token to its mailbox so the node can wake it on delivery."""
        self._push.register(mailbox, token)
        return {"ok": True}

    # -- blind server-half custody (holds an OPAQUE sealed share it cannot open) ---------------
    # This node stores a Shamir share of some user's server_half, sealed under a key only that user
    # can derive, indexed by an OPAQUE locator (H(recovery_selector, node_id, epoch)). The node
    # cannot read the share, cannot tell whose it is, and a share alone reveals nothing about any
    # seed. See atlas.keys.server_custody. Persisted to disk so custody survives a restart; keyed
    # by the hex locator, which leaks nothing.
    def _custody_dir(self) -> str:
        import os
        base = os.environ.get("ATLAS_STORAGE", "/var/lib/atlas")
        d = os.path.join(base, "custody")
        try:
            os.makedirs(d, exist_ok=True)
        except OSError:
            d = "atlas-custody"
            os.makedirs(d, exist_ok=True)
        return d

    @staticmethod
    def _safe_locator(locator: str) -> str:
        # locators are hex (from H(...)); reject anything that isn't, so no path traversal.
        loc = locator.strip().lower()
        if not loc or len(loc) > 128 or any(c not in "0123456789abcdef" for c in loc):
            raise ValueError("locator must be lowercase hex")
        return loc

    def custody_put(self, *, locator: str, blob_b64: str) -> dict:
        import base64
        import os
        loc = self._safe_locator(locator)
        raw = base64.b64decode(blob_b64)
        with open(os.path.join(self._custody_dir(), f"{loc}.share"), "wb") as fh:
            fh.write(raw)
        return {"ok": True, "locator": loc, "bytes": len(raw)}

    def custody_get(self, *, locator: str) -> dict:
        import base64
        import os
        loc = self._safe_locator(locator)
        path = os.path.join(self._custody_dir(), f"{loc}.share")
        if not os.path.exists(path):
            raise KeyError(f"no custody share at {loc}")
        with open(path, "rb") as fh:
            raw = fh.read()
        return {"locator": loc, "blob": base64.b64encode(raw).decode()}

    def custody_drop(self, *, locator: str) -> dict:
        import os
        loc = self._safe_locator(locator)
        path = os.path.join(self._custody_dir(), f"{loc}.share")
        existed = os.path.exists(path)
        if existed:
            os.remove(path)
        return {"ok": True, "locator": loc, "dropped": existed}

    # -- public EPOCH beacon: CONSUMED from the Atlas aggregator, not run here -------------------
    # The relay does not own the aggregator key or run the epoch beacon (that is Atlas-server
    # infrastructure, `beacon.epoch_service.EpochBeaconService`). It fetches signed epoch rounds from
    # `self._epoch_service`, verifies each against the pinned aggregator key, and serves them.
    def _storage_base(self) -> str:
        import os
        base = os.environ.get("ATLAS_STORAGE", "/var/lib/atlas")
        try:
            os.makedirs(base, exist_ok=True)
        except OSError:
            base = "atlas-storage"
            os.makedirs(base, exist_ok=True)
        return base

    def _drand_anchor(self):
        """The current external-drand round as the defence-in-depth anchor, or None if the relay is
        unreachable (the epoch beacon fires regardless — drand is optional, not the key)."""
        try:
            from ..beacon.drand import DrandHTTPBeacon
            r = DrandHTTPBeacon().latest()
            return r.round, r.epoch_round()
        except Exception:
            return None

    def relay_fetch(self, *, mailbox: str) -> dict:
        """Deliver + clear the recipient's pending opaque blobs. The recipient
        decrypts them locally with the A-B key (never on the node)."""
        mb = self._mailboxes.get(mailbox)
        if mb is None:
            return {"messages": []}   # polling a not-yet-written rotating box is a no-op, not an error
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
            self._registry.publish(bytes.fromhex(lk_hex_TESTONLY), b.epoch_round)
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

    def register_witness_public(self, *, epoch_round: bytes, pub) -> None:
        """A phone (LK holder) publishes ONLY the epoch witness PUBLIC half here so
        recipients can verify live-provenance WITHOUT the LK. Reveals nothing."""
        self._registry.register_public(epoch_round, pub)

    def witness_public(self, epoch_round: bytes):
        return self._registry.witness_pub(epoch_round)

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

    # -- public timekeeper: the node heartbeats on external drand even with zero devices ------
    # External drand is NOT the epoch key (that is the aggregator's QRNG `beacon.epoch`); it is the
    # BOOTSTRAP / defence-in-depth ANCHOR (public, party-neutral, never a key). The node serves the
    # latest BLS-VERIFIED round at /beacon so that, before/independent of the epoch beacon, devices
    # have a common public timeline, ledger anchors get verifiable party-neutral timestamps, and
    # cover-traffic batching can tick on a constant public rhythm regardless of load. Cached ~10s;
    # falls back to the last verified round if a drand relay fetch hiccups (still a real, verified round).
    _beacon_cache: tuple[float, dict] | None = None

    def _drand_bootstrap(self) -> dict:
        """A bare relay with no Atlas epoch service configured serves the external-drand round as the
        BOOTSTRAP public timeline (honestly labelled — this is drand's bootstrap role, not the epoch
        key). Fail-closed: if drand is unreachable too, report unavailable rather than fabricate."""
        anchor = self._drand_anchor()
        if anchor is None:
            return {"error": "no epoch service and drand unreachable", "verified": False}
        return {"round": anchor[0], "epoch_round": anchor[1].hex(), "verified": True,
                "source": "drand-bootstrap"}

    def beacon_now(self) -> dict:
        import time as _t
        if self._beacon_cache and _t.time() - self._beacon_cache[0] < 10:
            return self._beacon_cache[1]
        try:
            if self._epoch_service is None:
                out = self._drand_bootstrap()             # no Atlas aggregator wired: bootstrap only
                self._beacon_cache = (_t.time(), out)
                return out
            from ..beacon import verify_epoch_round
            anchor = self._drand_anchor()                 # (round, bytes) or None if drand unreachable
            anchor_bytes = anchor[1] if anchor else b""
            # Fetch the latest signed epoch round from the Atlas aggregator and VERIFY it against the
            # pinned aggregator key BEFORE serving — the relay trusts nothing it cannot verify.
            rnd = self._epoch_service.current(anchor=anchor_bytes)
            pub = self._epoch_service.public
            if not verify_epoch_round(rnd, pub):
                raise ValueError("epoch round failed aggregator-signature verification")
            out = {
                "epoch": rnd.epoch,
                "epoch_round": rnd.epoch_round().hex(),
                "randomness": rnd.randomness.hex(),
                "signature": rnd.signature.hex(),
                "aggregator_pub": pub.encode().hex(),
                "anchor_drand_round": (anchor[0] if anchor else None),
                "anchor": anchor_bytes.hex(),
                "verified": True,
                "source": "atlas-epoch-beacon",       # the epoch key is the QRNG epoch — NOT drand
            }
            self._beacon_cache = (_t.time(), out)
            return out
        except Exception as e:  # never 500 the timekeeper
            if self._beacon_cache:
                stale = dict(self._beacon_cache[1])
                stale["stale"] = True
                return stale
            return {"error": f"beacon unavailable: {e}", "verified": False}

    # -- inheritance-gated custody: arm / trigger / veto / serve --------------------------------
    # The custodian holds an OPAQUE sealed heir share and can release it ONLY when the gate opens:
    # the attorney/representative fired a death-trigger, the time-lock elapsed, and the owner did not
    # veto by proving liveness. The gate is clocked on EXTERNAL DRAND — deliberately: a death-trigger
    # and challenge window is a court-contestable legal event, so its clock must be the PARTY-NEUTRAL,
    # third-party/court-verifiable public timeline (drand in its anchor role — NOT drand as the epoch
    # key, which is the aggregator's QRNG `beacon.epoch`). State is persisted, so a reboot cannot
    # reopen a fired challenge, and a veto's freshness signature is verified against drand before it
    # is accepted (a fabricated `beacon_sig` cannot pass off a pre-signed veto).
    def _inheritance(self):
        if getattr(self, "_inh_store", None) is None:
            import os
            import time as _t
            from ..beacon.drand import DrandHTTPBeacon, QUICKNET_PUBLIC_KEY, verify_drand_signature
            pub = bytes.fromhex(QUICKNET_PUBLIC_KEY)
            self._inh_store = __import__(
                "atlas.keys.inheritance_store", fromlist=["InheritanceStore"]).InheritanceStore(
                os.path.join(self._storage_base(), "inheritance"),
                current_round=lambda: DrandHTTPBeacon().round_number_at(_t.time()),
                verify_round=lambda r, sig: verify_drand_signature(r, sig, pub))
        return self._inh_store

    def inherit_arm(self, *, locator: str, heir_blob_b64: str, gate_id_hex: str,
                    owner_pub_b64: str, trigger_pub_b64: str, veto_window_rounds) -> dict:
        import base64
        from ..crypto.sign import HybridSigPublic
        self._inheritance().arm(
            locator=locator, heir_blob=base64.b64decode(heir_blob_b64), gate_id=bytes.fromhex(gate_id_hex),
            owner_pub=HybridSigPublic.decode(base64.b64decode(owner_pub_b64)),
            trigger_pub=HybridSigPublic.decode(base64.b64decode(trigger_pub_b64)),
            veto_window_rounds=int(veto_window_rounds))
        return {"ok": True, "locator": locator, "status": self._inheritance().status(locator=locator)}

    def inherit_trigger(self, *, locator: str, at_round, signature_b64: str) -> dict:
        import base64
        st = self._inheritance().trigger(locator=locator, at_round=int(at_round),
                                         signature=base64.b64decode(signature_b64))
        return {"ok": True, "locator": locator, "status": st}

    def inherit_veto(self, *, locator: str, at_round, beacon_sig_b64: str, signature_b64: str) -> dict:
        import base64
        st = self._inheritance().veto(locator=locator, at_round=int(at_round),
                                      beacon_sig=base64.b64decode(beacon_sig_b64),
                                      signature=base64.b64decode(signature_b64))
        return {"ok": True, "locator": locator, "status": st}

    def inherit_serve(self, *, locator: str) -> dict:
        import base64
        blob = self._inheritance().serve(locator=locator)   # raises NotReleasable unless the gate is open
        return {"ok": True, "locator": locator, "heir_blob": base64.b64encode(blob).decode()}

    def inherit_status(self, *, locator: str) -> dict:
        return {"locator": locator, "status": self._inheritance().status(locator=locator)}

    # -- duress evidence sink: sealed sensor evidence streamed OFF the device -------------
    # A phone under coercion streams a SEALED evidence blob here (sensor snapshot + timestamp).
    # The node CANNOT read it (client-sealed) — but it holds it append-only, off the device, so a
    # coercer who wipes/keeps the phone cannot destroy the record. Anti-forensic durability, not
    # surveillance: the node stores ciphertext it can't open, exactly like a mailbox blob.
    def duress_record(self, *, blob_b64: str, meta: str = "") -> dict:
        import base64
        import os
        import time
        raw = base64.b64decode(blob_b64)
        store = os.environ.get("ATLAS_STORAGE", "/var/lib/atlas")
        ddir = os.path.join(store, "duress")
        try:
            os.makedirs(ddir, exist_ok=True)
        except OSError:
            ddir = "atlas-duress"
            os.makedirs(ddir, exist_ok=True)
        # sequence by wall clock ns; the FILENAME leaks only arrival time, the CONTENT is sealed.
        name = f"{int(time.time() * 1e9)}.evd"
        with open(os.path.join(ddir, name), "wb") as fh:
            fh.write(raw)
        return {"ok": True, "stored": name, "bytes": len(raw)}

    def search_proxy(self, path: str) -> dict:
        """Proxy the AI's wider-web search to the node-local SearXNG (127.0.0.1:8888), so the phone
        reaches it over the node's HTTPS (Caddy) rather than an exposed HTTP port — keeps searx
        private and satisfies the app's HTTPS-only transport policy. Returns SearXNG's JSON."""
        import json as _json
        import os
        import urllib.parse
        import urllib.request
        from urllib.parse import parse_qs, urlsplit
        query = parse_qs(urlsplit(path).query)
        # OPTIONAL AUTH: if the operator sets ATLAS_SEARCH_TOKEN, require it — so an exposed node is not
        # an open search proxy for anyone. Unset -> open (unchanged), but the operator can lock it down
        # and the app then sends ?token=…. SSRF-safe already (pinned loopback URL; only `q` passes through).
        want = os.environ.get("ATLAS_SEARCH_TOKEN")
        if want and (query.get("token", [""])[0]) != want:
            return {"results": [], "error": "unauthorized"}
        q = (query.get("q", [""])[0]).strip()
        if not q:
            return {"results": []}
        url = "http://127.0.0.1:8888/search?" + urllib.parse.urlencode({"q": q, "format": "json"})
        try:
            with urllib.request.urlopen(url, timeout=8) as r:
                return _json.loads(r.read().decode("utf-8", "replace"))
        except Exception as e:  # noqa: BLE001
            return {"results": [], "error": f"{type(e).__name__}: {e}"}

    def did_register(self, *, public_key_b64: str) -> dict:
        """Publish a persona's public key under its DIDs so the verifier can RESOLVE it — the app then
        posts only the token. Self-certifying: did:cid IS the hash of the key, and kid = kid_of(key),
        so a registration can't lie about which key it is. (In-memory here; a durable, replicated
        registry is the 'recognition web' — the part that's a subscription.)"""
        import base64 as _b64
        from ..crypto.sign import HybridSigPublic
        from ..did_cid import did_for
        from ..interop.assertion import kid_of
        try:
            pub = HybridSigPublic.decode(_b64.b64decode(public_key_b64))
        except Exception:
            return {"ok": False, "error": "bad public_key"}
        kid = kid_of(pub)
        dcid = did_for(pub)
        for key in (kid, "did:atlas:" + kid, dcid):
            self._did_registry[key] = pub
        return {"ok": True, "did_atlas": "did:atlas:" + kid, "did_cid": dcid, "kid": kid}

    def _resolve_from_token(self, token: str):
        """Resolve the presenter's public key from a JWS's `kid` header / `iss` DID via the registry."""
        import base64 as _b64
        import json as _json
        try:
            parts = token.split(".")
            hdr = _json.loads(_b64.urlsafe_b64decode(parts[0] + "=="))
            if (kid := hdr.get("kid")) and kid in self._did_registry:
                return self._did_registry[kid]
            payload = _json.loads(_b64.urlsafe_b64decode(parts[1] + "=="))
            if (iss := payload.get("iss")) and iss in self._did_registry:
                return self._did_registry[iss]
        except Exception:
            return None
        return None

    def verify_presence(self, *, credential_format: str, token: str, public_key_b64: Optional[str] = None,
                        audience: Optional[str] = None, min_tier: int = 1) -> dict:
        """CONSUMABLE verifier (the 'verified-human as a service' endpoint). An app POSTs a presented
        Atlas credential (a 'vc' JWS or an 'oidc' id_token) and gets back {valid, verified_human,
        assurance_tier, epoch, subject}. The presenter's key is RESOLVED from the token's DID (via
        /did/register) — or passed explicitly as `public_key`. Offline-verifiable by signature; this
        hosted endpoint is a convenience. The node learns a check happened but not who."""
        import base64 as _b64
        from ..crypto.sign import HybridSigPublic
        from ..interop import oidc, vc
        if public_key_b64:
            try:
                pub = HybridSigPublic.decode(_b64.b64decode(public_key_b64))
            except Exception:
                return {"valid": False, "error": "bad public_key"}
        else:
            pub = self._resolve_from_token(token)
            if pub is None:
                return {"valid": False, "error": "unresolved presenter — register the DID (/did/register) or pass public_key"}
        if credential_format == "oidc":
            claims = oidc.verify_id_token(pub, token, audience=audience)
            if claims is None:
                return {"valid": False}
            vh = bool(claims.get("atlas_verified_human", False))
            tier = int(claims.get("assurance_tier", 0))
            epoch, subject = claims.get("epoch"), claims.get("sub")
        else:
            claims = vc.verify_jws(pub, token)
            if claims is None:
                return {"valid": False}
            cs = claims.get("vc", {}).get("credentialSubject", {})
            vh = bool(cs.get("verified_human", False))
            tier = int(cs.get("assurance_tier", 0))
            epoch, subject = (claims.get("atlas") or {}).get("epoch"), cs.get("id")
        return {"valid": vh and tier >= int(min_tier), "verified_human": vh,
                "assurance_tier": tier, "epoch": epoch, "subject": subject}

    def provenance_embed(self, *, content_b64: str, fmt: str, vc_jws: str, issuer_did: str,
                         verdict: str, title: str = "Atlas provenance") -> dict:
        """C2PA embed service — bakes a presence VC into content (image OR PDF) as a signed C2PA
        manifest. Runs where the c2pa native lib lives (this node); returns the embedded asset. The
        phone computes the VC + verdict + issuer DID (interop.presence_interop) and posts them here."""
        from ..interop import c2pa as c2
        try:
            c2._require_c2pa()
        except Exception as e:  # honest: the last mile needs the native lib
            return {"ok": False, "error": f"c2pa unavailable: {e}"}
        import base64 as _b64
        import os
        import tempfile
        suffix = {"application/pdf": ".pdf", "image/jpeg": ".jpg"}.get(fmt, ".png")
        cert_chain_pem, key_pem, _ca = c2.make_test_signer()
        src = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
        src.write(_b64.b64decode(content_b64)); src.close()
        dst = src.name + ".signed"
        try:
            c2.embed_assertion(src.name, dst, vc_jws=vc_jws, issuer_did=issuer_did, verdict=verdict,
                               cert_chain_pem=cert_chain_pem, key_pem=key_pem, fmt=fmt, title=title)
            with open(dst, "rb") as f:
                return {"ok": True, "asset_b64": _b64.b64encode(f.read()).decode()}
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}
        finally:
            for p in (src.name, dst):
                try:
                    os.remove(p)
                except OSError:
                    pass

    def dispatch(self, method: str, path: str, body: dict):
        try:
            if method == "GET" and path in ("/", "/dashboard"):
                return 200, ("html", self.dashboard_html())
            if method == "GET" and path == "/status":
                return 200, ("json", self.status())
            if method == "GET" and path == "/beacon":
                return 200, ("json", self.beacon_now())
            if method == "GET" and path.startswith("/search"):
                return 200, ("json", self.search_proxy(path))
            if method == "POST" and path == "/did/register":
                return 200, ("json", self.did_register(public_key_b64=body["public_key"]))
            if method == "POST" and path == "/verify/presence":
                return 200, ("json", self.verify_presence(
                    credential_format=body.get("format", "vc"), token=body["token"],
                    public_key_b64=body.get("public_key"), audience=body.get("audience"),
                    min_tier=int(body.get("min_tier", 1))))
            if method == "POST" and path == "/provenance/embed":
                return 200, ("json", self.provenance_embed(
                    content_b64=body["content"], fmt=body.get("fmt", "image/png"),
                    vc_jws=body["vc_jws"], issuer_did=body["issuer_did"],
                    verdict=body["verdict"], title=body.get("title", "Atlas provenance")))
            if method == "POST" and path == "/duress":
                return 200, ("json", self.duress_record(blob_b64=body["blob"],
                                                         meta=body.get("meta", "")))
            if method == "POST" and path == "/push/register":
                return 200, ("json", self.push_register(mailbox=body["mailbox"], token=body["token"]))
            if method == "POST" and path == "/relay/register":
                return 200, ("json", self.register(mailbox=body["mailbox"], kem_pub=body["kem_pub"]))
            if method == "GET" and path.startswith("/relay/pubkey/"):
                return 200, ("json", self.peer_pubkey(path.rsplit("/", 1)[-1]))
            if method == "POST" and path == "/relay/send":
                # `from` is optional and ignored (sealed-sender) — routing is on `to` only.
                return 200, ("json", self.relay_send(to=body["to"], blob_b64=body["blob"],
                                                     frm=body.get("from", "")))
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
            if method == "POST" and path == "/custody/put":
                return 200, ("json", self.custody_put(locator=body["locator"], blob_b64=body["blob"]))
            if method == "GET" and path.startswith("/custody/get/"):
                return 200, ("json", self.custody_get(locator=path.rsplit("/", 1)[-1]))
            if method == "POST" and path == "/custody/drop":
                return 200, ("json", self.custody_drop(locator=body["locator"]))
            if method == "POST" and path == "/publish/provenance":
                return 200, ("json", self.publish_provenance(
                    bundle=body["bundle"], content_b64=body.get("content_b64", ""),
                    lk_hex_TESTONLY=body.get("lk_hex_TESTONLY", "")))
            if method == "POST" and path == "/inherit/arm":
                return 200, ("json", self.inherit_arm(
                    locator=body["locator"], heir_blob_b64=body["heir_blob"], gate_id_hex=body["gate_id"],
                    owner_pub_b64=body["owner_pub"], trigger_pub_b64=body["trigger_pub"],
                    veto_window_rounds=body["veto_window_rounds"]))
            if method == "POST" and path == "/inherit/trigger":
                return 200, ("json", self.inherit_trigger(
                    locator=body["locator"], at_round=body["at_round"], signature_b64=body["signature"]))
            if method == "POST" and path == "/inherit/veto":
                return 200, ("json", self.inherit_veto(
                    locator=body["locator"], at_round=body["at_round"],
                    beacon_sig_b64=body["beacon_sig"], signature_b64=body["signature"]))
            if method == "GET" and path.startswith("/inherit/serve/"):
                return 200, ("json", self.inherit_serve(locator=path.rsplit("/", 1)[-1]))
            if method == "GET" and path.startswith("/inherit/status/"):
                return 200, ("json", self.inherit_status(locator=path.rsplit("/", 1)[-1]))
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


def serve(host: str = "0.0.0.0", port: int = 8787) -> None:  # nosec B104 - intentional LAN bind: LAN phones reach the Mac node; override with --host
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    # Single-process PoC server: run a local Atlas aggregator (persisted key) as the epoch source.
    # In a real deployment the aggregator is a SEPARATE Atlas-operated service and this relay would be
    # given an authenticated client to it (with the aggregator key pinned), never run it in-process.
    import os as _os
    from ..beacon import EpochBeaconService
    agg = EpochBeaconService(storage_dir=_os.path.join(
        _os.environ.get("ATLAS_STORAGE", "atlas-storage"), "aggregator"))
    node = AtlasNode(port=port, epoch_service=agg)

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
    import os as _os
    ap = argparse.ArgumentParser(description="Atlas node — blind relay + opt-in public verifier")
    ap.add_argument("--host", default="0.0.0.0")  # nosec B104 - LAN bind so phones can reach the node; pass --host 127.0.0.1 to restrict
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--public", action="store_true",
                    help="node is reachable from the open internet: enforce the constant-time "
                         "ML-KEM guard at startup (fails closed on the reference backend)")
    args = ap.parse_args()
    if args.public or _os.environ.get("ATLAS_PUBLIC") == "1":
        from ..crypto.kem import require_constant_time_kem
        require_constant_time_kem()   # security review #7: never expose timing-leaky decap
        print("[atlas-node] PUBLIC mode: constant-time ML-KEM verified (liboqs)")
    serve(args.host, args.port)
