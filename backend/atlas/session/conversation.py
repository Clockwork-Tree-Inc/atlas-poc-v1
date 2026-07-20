"""Conversation state model over the forward-secret chain (§2.2, §10.1).

`fs_conversation.FSChain` gives one forward-secret directional chain: seal/open
advance a one-way HKDF ratchet in lockstep. A real conversation needs the state
machine ON TOP of it — this module — so the Swift messaging UI has an exact
reference:

  * ORDERING          — every message carries an index; the receiver tracks the
                        next expected position.
  * OUT-OF-ORDER      — a message that arrives ahead of earlier ones is opened via
                        a bounded skipped-message-key cache (Signal-style), and
                        the earlier ones still open when they arrive.
  * REPLAY            — a consumed (or unknown) index is refused, fail-closed.
  * PERSISTENCE       — the chain position (chain key + counter + skipped keys)
                        serializes and restores, so both sides resume in LOCKSTEP
                        after an app restart. Identity keys are NOT serialized;
                        they reload from the identity tree / Enclave.
  * MODE (per chat)   — ACCOUNTABLE: each message is additionally signed by the
                        sender's authorship pseudonym, bound to (content, index,
                        direction, epoch) — non-repudiable, "who said what" is
                        provable. DENIABLE: symmetric AEAD auth only; both parties
                        hold the message key, so a transcript proves neither
                        authored it — deniable by construction.

FORWARD SECRECY (honest boundary): consumed message keys are discarded and the
chain key only advances forward, so a later state cannot derive an earlier
message key. Skipped-but-unconsumed keys are held in a BOUNDED cache
(`MAX_SKIP`) until their message arrives — that cache is the standard, bounded
exposure; compromise of stored state leaks only those still-pending keys, never
consumed or future ones.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional

from ..crypto.primitives import H, aead_decrypt, aead_encrypt
from ..crypto.sign import HybridSigPublic, sign, verify
from ..keys.identity import Child
from .fs_conversation import _step, seed_chain

MAX_SKIP = 256                              # bound on out-of-order look-ahead


class ConversationMode(Enum):
    ACCOUNTABLE = "accountable"             # signed, non-repudiable ("who said what" provable)
    DENIABLE = "deniable"                   # symmetric-auth only -> deniable transcript


class ReplayError(Exception):
    """A message index was already consumed, or is unknown (fail-closed)."""


class TooManySkipped(Exception):
    """The receiver was asked to skip more than MAX_SKIP messages (DoS guard)."""


class SignatureRejected(Exception):
    """ACCOUNTABLE mode: the authorship signature did not verify for this
    (content, index, direction, epoch) — refused."""


def _aad(direction: bytes, index: int, drand_round: bytes) -> bytes:
    """Bind each ciphertext to its position so it cannot be replayed at another
    index / direction / epoch (the AEAD open fails if any differ)."""
    return H(b"atlas/conv/aad", direction, index.to_bytes(8, "big"), drand_round)


def _sig_core(content: bytes, direction: bytes, index: int, drand_round: bytes) -> bytes:
    """The accountable signing core: binds WHO (via the signing key) to WHAT
    (content) at WHICH position (index/direction/epoch)."""
    return H(b"atlas/conv/sig-core", H(b"atlas/conv/content", content),
             direction, index.to_bytes(8, "big"), drand_round)


@dataclass
class Envelope:
    """One wire message. `signature` is present iff the chat is ACCOUNTABLE."""

    index: int
    direction: bytes
    drand_round: bytes
    ciphertext: bytes
    signature: bytes = b""

    def to_wire(self) -> bytes:
        return json.dumps({
            "i": self.index, "d": _b64(self.direction), "e": _b64(self.drand_round),
            "c": _b64(self.ciphertext), "s": _b64(self.signature),
        }).encode()

    @staticmethod
    def from_wire(blob: bytes) -> "Envelope":
        o = json.loads(blob)
        return Envelope(index=o["i"], direction=_u(o["d"]), drand_round=_u(o["e"]),
                        ciphertext=_u(o["c"]), signature=_u(o["s"]))


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _u(s: str) -> bytes:
    return base64.b64decode(s)


class _SendChain:
    """The sender's own direction: seal in sequence, index increments."""

    def __init__(self, ck: bytes, *, drand_round: bytes, beacon_t: bytes, index: int = 0):
        self._ck = ck
        self.drand_round = drand_round
        self._beacon_t = beacon_t
        self._i = index

    def seal(self, plaintext: bytes, direction: bytes):
        mk, nxt = _step(self._ck, beacon_t=self._beacon_t, drand_round=self.drand_round)
        i = self._i
        self._ck = nxt                       # advance; old chain key discarded
        self._i += 1
        ct = aead_encrypt(mk, plaintext, aad=_aad(direction, i, self.drand_round))
        return i, ct

    def snapshot(self) -> dict:
        return {"ck": _b64(self._ck), "epoch": _b64(self.drand_round),
                "beacon": _b64(self._beacon_t), "i": self._i}

    @classmethod
    def restore(cls, s: dict) -> "_SendChain":
        return cls(_u(s["ck"]), drand_round=_u(s["epoch"]), beacon_t=_u(s["beacon"]), index=s["i"])


class _RecvChain:
    """The peer's direction: open in order OR out of order via a bounded skipped
    message-key cache; refuse replays."""

    def __init__(self, ck: bytes, *, drand_round: bytes, beacon_t: bytes,
                 nxt: int = 0, skipped: Optional[Dict[int, bytes]] = None):
        self._ck = ck
        self.drand_round = drand_round
        self._beacon_t = beacon_t
        self._next = nxt
        self._skipped: Dict[int, bytes] = dict(skipped or {})

    def open(self, index: int, ciphertext: bytes, direction: bytes) -> bytes:
        if index < self._next:
            mk = self._skipped.pop(index, None)
            if mk is None:
                raise ReplayError(f"message {index} already consumed or unknown")
        else:
            if index - self._next > MAX_SKIP:
                raise TooManySkipped(f"skip {index - self._next} > {MAX_SKIP}")
            while self._next < index:                     # cache the skipped keys
                mk, nxt = _step(self._ck, beacon_t=self._beacon_t, drand_round=self.drand_round)
                self._skipped[self._next] = mk
                self._ck = nxt
                self._next += 1
            mk, nxt = _step(self._ck, beacon_t=self._beacon_t, drand_round=self.drand_round)
            self._ck = nxt                                # consume this index
            self._next += 1
        return aead_decrypt(mk, ciphertext, aad=_aad(direction, index, self.drand_round))

    def snapshot(self) -> dict:
        return {"ck": _b64(self._ck), "epoch": _b64(self.drand_round),
                "beacon": _b64(self._beacon_t), "next": self._next,
                "skipped": {str(i): _b64(mk) for i, mk in self._skipped.items()}}

    @classmethod
    def restore(cls, s: dict) -> "_RecvChain":
        return cls(_u(s["ck"]), drand_round=_u(s["epoch"]), beacon_t=_u(s["beacon"]),
                   nxt=s["next"], skipped={int(i): _u(mk) for i, mk in s["skipped"].items()})


class Conversation:
    """One party's view of a two-party conversation: a send chain (my direction)
    and a receive chain (the peer's direction), plus the per-chat mode.

    Both parties derive the SAME per-direction seed from shared live material
    (static KEM channel key + live co-derived LK + epoch), so A's send chain and
    B's receive chain for the A->B direction are identical — lockstep with no
    per-message secret transmitted.
    """

    def __init__(self, *, mode: ConversationMode, my_direction: bytes, peer_direction: bytes,
                 send: _SendChain, recv: _RecvChain,
                 authorship: Optional[Child] = None, peer_public: Optional[HybridSigPublic] = None):
        if mode is ConversationMode.ACCOUNTABLE and authorship is None:
            raise ValueError("ACCOUNTABLE chat requires the sender's authorship child")
        self._mode = mode
        self._my_dir = my_direction
        self._peer_dir = peer_direction
        self._send = send
        self._recv = recv
        self._authorship = authorship
        self._peer_public = peer_public

    @classmethod
    def create(cls, *, mode: ConversationMode, my_direction: bytes, peer_direction: bytes,
               channel_key: bytes, lk: bytes, drand_round: bytes, beacon_t: bytes,
               authorship: Optional[Child] = None,
               peer_public: Optional[HybridSigPublic] = None) -> "Conversation":
        s_seed = seed_chain(channel_key=channel_key, lk=lk, drand_round=drand_round, direction=my_direction)
        r_seed = seed_chain(channel_key=channel_key, lk=lk, drand_round=drand_round, direction=peer_direction)
        return cls(mode=mode, my_direction=my_direction, peer_direction=peer_direction,
                   send=_SendChain(s_seed, drand_round=drand_round, beacon_t=beacon_t),
                   recv=_RecvChain(r_seed, drand_round=drand_round, beacon_t=beacon_t),
                   authorship=authorship, peer_public=peer_public)

    @property
    def mode(self) -> ConversationMode:
        return self._mode

    def send(self, plaintext: bytes) -> Envelope:
        index, ct = self._send.seal(plaintext, self._my_dir)
        sig = b""
        if self._mode is ConversationMode.ACCOUNTABLE:
            core = _sig_core(plaintext, self._my_dir, index, self._send.drand_round)
            sig = sign(self._authorship.keypair, core)
        return Envelope(index=index, direction=self._my_dir, drand_round=self._send.drand_round,
                        ciphertext=ct, signature=sig)

    def receive(self, env: Envelope) -> bytes:
        plaintext = self._recv.open(env.index, env.ciphertext, env.direction)
        if self._mode is ConversationMode.ACCOUNTABLE:
            if self._peer_public is None:
                raise SignatureRejected("ACCOUNTABLE chat: no peer authorship public to verify against")
            core = _sig_core(plaintext, env.direction, env.index, env.drand_round)
            if not verify(self._peer_public, core, env.signature):
                raise SignatureRejected(f"message {env.index}: authorship signature invalid")
        return plaintext

    # -- persistence: chain position survives an app restart, keys reload from tree
    def serialize(self) -> bytes:
        return json.dumps({
            "mode": self._mode.value,
            "my_dir": _b64(self._my_dir), "peer_dir": _b64(self._peer_dir),
            "send": self._send.snapshot(), "recv": self._recv.snapshot(),
        }).encode()

    @classmethod
    def deserialize(cls, blob: bytes, *, authorship: Optional[Child] = None,
                    peer_public: Optional[HybridSigPublic] = None) -> "Conversation":
        o = json.loads(blob)
        return cls(mode=ConversationMode(o["mode"]),
                   my_direction=_u(o["my_dir"]), peer_direction=_u(o["peer_dir"]),
                   send=_SendChain.restore(o["send"]), recv=_RecvChain.restore(o["recv"]),
                   authorship=authorship, peer_public=peer_public)
