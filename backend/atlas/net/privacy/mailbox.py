"""Rotating mailboxes + sealed sender — deny the relay the social graph.

The contact layer (atlas/contact.py) gives verified, spoof/spam-proof reachability, and the
transport layer (transport.py) hides message SIZE and TIMING with padding + batching + cover.
Both, though, still let the relay see STABLE handles: a stable "to" address, held over time, is
itself the social graph — who talks to whom, how often, when. This module removes that last
metadata leak.

Two ideas do it:

  ROTATING MAILBOX. Once two parties are connected they share a `pair_secret` (established by the
  recognition-tunnel handshake — out of scope here, injected). Neither party's address is a stable
  handle; instead each (pair, direction, epoch) hashes under the shared secret to a fresh opaque
  mailbox id. The `epoch` is a public shared clock (a beacon round), so both endpoints derive the
  SAME id for the current epoch without coordinating, while the relay — which lacks `pair_secret` —
  sees an unlinkable fresh 16 bytes every epoch. It cannot tell that this epoch's mailbox and last
  epoch's are the same conversation, nor correlate one contact's mailboxes with another's.

  SEALED SENDER. The relay routes purely on the rotating mailbox id; the SENDER's identity lives
  INSIDE the sealed blob, so the relay learns neither who sent nor (beyond the opaque id) who
  receives. Only the holder of `pair_secret` opens it and learns which contact/persona it is from.

Cold first contact (no `pair_secret` yet) uses a PUBLIC INBOX: an opt-in, deliberately STABLE
mailbox derived from a persona's published key, to which anyone may seal a first-contact message
(sealed to that published key). The contact layer's Sybil-bounded rate-limit + screening still
apply; on accept the parties establish a `pair_secret` and move to rotating mailboxes.

The SealedEnvelope.blob is exactly what rides transport.py's PrivacyChannel (padded to the cell,
batched with cover) — this module owns WHO/rotation, that module owns SIZE/TIMING; composed, the
relay sees uniform blobs to unlinkable rotating addresses with no sender. Reference-of-record.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from ...crypto.primitives import H, aead_decrypt, aead_encrypt, hkdf

MAILBOX_BYTES = 16          # opaque routing id the relay sees (rotates per pair/direction/epoch)


class MailboxError(Exception):
    ...


# --------------------------------------------------------------------------- #
# Rotating mailbox derivation
# --------------------------------------------------------------------------- #
def _dir_label(sender: bytes, recipient: bytes) -> bytes:
    """A stable per-direction tag both endpoints agree on without extra coordination.

    Sorting the two party ids gives a canonical (low, high) pair; the sender being the low
    or the high party picks the label. So A->B and B->A get DIFFERENT mailboxes (inbound and
    outbound never collide), and both endpoints compute the same label for a given direction."""
    lo, _hi = sorted((sender, recipient))
    return b"\x00" if sender == lo else b"\x01"


def derive_mailbox(pair_secret: bytes, *, sender: bytes, recipient: bytes, epoch: bytes) -> bytes:
    """The rotating mailbox id for `sender`->`recipient` in `epoch`. Both endpoints derive it
    from the shared `pair_secret`; the relay, lacking the secret, sees fresh unlinkable bytes
    each epoch. Party ids only pick the direction label — they are NOT in the digest, so the id
    reveals nothing about the parties even to someone who guesses them without the secret."""
    if not pair_secret:
        raise MailboxError("pair_secret required")
    return H(b"atlas/mailbox/v1", pair_secret, _dir_label(sender, recipient), epoch)[:MAILBOX_BYTES]


def _msg_key(pair_secret: bytes, epoch: bytes) -> bytes:
    """Per-epoch content key for an established pair. Rotates with the mailbox so a compromise
    of one epoch's key does not open other epochs' blobs sitting at the relay."""
    return hkdf(ikm=pair_secret, info=b"atlas/mailbox/msgkey/v1" + epoch)


# --------------------------------------------------------------------------- #
# Beacon clock + catch-up window (TOTP-style)
# --------------------------------------------------------------------------- #
def epoch_for_round(round_number: int) -> bytes:
    """The rotation epoch for a drand beacon round. The round INDEX is the public shared clock:
    both endpoints derive the SAME mailbox for the same round without coordinating — exactly like a
    TOTP time-step, but the step is a verifiable beacon round instead of local wall-clock."""
    if round_number < 0:
        raise MailboxError("round_number must be >= 0")
    return struct.pack(">Q", round_number)


def catch_up_epochs(now_round: int, *, window: int) -> List[bytes]:
    """The recent epochs a recipient should poll so that being offline (or a clock skew of a few
    rounds between sender and receiver) never loses a message: rounds [now_round-window, now_round]
    inclusive, clamped at 0, NEWEST first. `window` is the TOTP-style tolerance — larger = more
    resilient to downtime/skew, at the cost of polling more mailboxes."""
    if window < 0:
        raise MailboxError("window must be >= 0")
    start = max(0, now_round - window)
    return [epoch_for_round(r) for r in range(now_round, start - 1, -1)]


# --------------------------------------------------------------------------- #
# Sealed-sender envelope
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class SealedEnvelope:
    """What the relay sees and routes on: a rotating mailbox id and an opaque blob. No sender,
    no recipient identity, no persona. `blob` is what PrivacyChannel pads + batches on the wire."""
    mailbox: bytes
    blob: bytes


def _frame(sender: bytes, seq: int, plaintext: bytes) -> bytes:
    return struct.pack(">H", len(sender)) + sender + struct.pack(">Q", seq) + plaintext


def _unframe(buf: bytes) -> Tuple[bytes, int, bytes]:
    (n,) = struct.unpack(">H", buf[:2])
    sender = buf[2:2 + n]
    (seq,) = struct.unpack(">Q", buf[2 + n:10 + n])
    return sender, seq, buf[10 + n:]


def seal_message(pair_secret: bytes, *, sender: bytes, recipient: bytes, epoch: bytes,
                 seq: int, plaintext: bytes) -> SealedEnvelope:
    """Seal `plaintext` for an established pair. The sender id is sealed INSIDE (sealed sender);
    the mailbox is bound as AEAD aad so a blob cannot be replayed under a different address."""
    mailbox = derive_mailbox(pair_secret, sender=sender, recipient=recipient, epoch=epoch)
    blob = aead_encrypt(_msg_key(pair_secret, epoch), _frame(sender, seq, plaintext), aad=mailbox)
    return SealedEnvelope(mailbox=mailbox, blob=blob)


def open_message(pair_secret: bytes, envelope: SealedEnvelope, *, epoch: bytes
                 ) -> Optional[Tuple[bytes, int, bytes]]:
    """Open a blob addressed to one of my rotating mailboxes -> (sender, seq, plaintext), or None
    if it is not mine / cover / corrupt (drop silently, like PrivacyChannel.receive)."""
    try:
        return _unframe(aead_decrypt(_msg_key(pair_secret, epoch), envelope.blob, aad=envelope.mailbox))
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Public inbox — opt-in cold first contact
# --------------------------------------------------------------------------- #
def public_inbox_id(persona_pub: bytes) -> bytes:
    """A deliberately STABLE mailbox derived from a persona's published key — the one address
    meant to be findable, for first contact before any pair_secret exists. Everything after the
    first accepted message moves to rotating per-contact mailboxes."""
    if not persona_pub:
        raise MailboxError("persona_pub required")
    return H(b"atlas/mailbox/public/v1", persona_pub)[:MAILBOX_BYTES]


def seal_first_contact(persona_pub: bytes, *, sender: bytes, plaintext: bytes,
                       seal_to_pub: Callable[[bytes], bytes]) -> SealedEnvelope:
    """Seal a cold first-contact message to a persona's PUBLISHED public key. `seal_to_pub` is the
    asymmetric seal (pqc_tunnel in production) — injected so this module stays crypto-core-decoupled.
    The relay still sees only (public mailbox, opaque blob); the sender is sealed inside."""
    return SealedEnvelope(mailbox=public_inbox_id(persona_pub),
                          blob=seal_to_pub(_frame(sender, 0, plaintext)))


# --------------------------------------------------------------------------- #
# Metadata-minimal relay
# --------------------------------------------------------------------------- #
@dataclass
class MailboxRelay:
    """The relay's ENTIRE view: a map from rotating mailbox id -> queued opaque blobs. It stores
    no handles, no sender, no recipient, no persona — nothing that survives an epoch to become a
    graph.

    NO DIRECTORY, POLLING-ONLY. There is deliberately no register()/enrollment step: the relay
    would otherwise hold a live list of "who is listening this epoch." Instead it learns a mailbox
    id ONLY when a blob is delivered to it or when it is polled. There is no server-held set of
    active boxes and no identity->mailbox map to see or leak; a box springs into existence on first
    delivery and vanishes on fetch."""
    _boxes: Dict[bytes, List[bytes]] = field(default_factory=dict)

    def deliver(self, envelope: SealedEnvelope) -> None:
        # The box springs into existence on first delivery; the relay never needs to know who it
        # is for, and never saw it declared.
        self._boxes.setdefault(envelope.mailbox, []).append(envelope.blob)

    def fetch(self, mailbox: bytes) -> List[bytes]:
        """Drain a mailbox. Returns [] for an unknown/empty id (no oracle: absence and empty look
        identical to a poller). The recipient derives which ids to poll from its own pair_secrets
        + the current epoch — it never asks the relay 'what boxes do I have?'."""
        return self._boxes.pop(mailbox, [])


# --------------------------------------------------------------------------- #
# Client endpoint — ties it together
# --------------------------------------------------------------------------- #
@dataclass
class _Contact:
    peer_id: bytes
    pair_secret: bytes
    seq: int = 0


class MailboxEndpoint:
    """A persona's client side: holds pair_secrets for its contacts and sends/receives sealed-
    sender blobs through a MailboxRelay. It derives which mailboxes to poll from its own secrets
    + the current epoch — it never enrolls or asks the relay what boxes it has (no directory).
    Barebones — no padding/batching here; wrap SealedEnvelope.blob in a PrivacyChannel for that."""

    def __init__(self, my_id: bytes, *, relay: MailboxRelay) -> None:
        self.my_id = my_id
        self._relay = relay
        self._contacts: Dict[bytes, _Contact] = {}

    def add_contact(self, peer_id: bytes, pair_secret: bytes) -> None:
        self._contacts[peer_id] = _Contact(peer_id, pair_secret)

    def send(self, peer_id: bytes, plaintext: bytes, *, epoch: bytes) -> SealedEnvelope:
        c = self._contacts.get(peer_id)
        if c is None:
            raise MailboxError("no such contact (need a pair_secret — use the public inbox first)")
        c.seq += 1
        env = seal_message(c.pair_secret, sender=self.my_id, recipient=peer_id,
                           epoch=epoch, seq=c.seq, plaintext=plaintext)
        self._relay.deliver(env)
        return env

    def send_at_round(self, peer_id: bytes, plaintext: bytes, *, now_round: int) -> SealedEnvelope:
        """Send stamped to the current beacon round's epoch — the beacon-clocked send path."""
        return self.send(peer_id, plaintext, epoch=epoch_for_round(now_round))

    def receive(self, peer_id: bytes, *, epoch: bytes) -> List[Tuple[int, bytes]]:
        """Pull and open everything from a contact this epoch -> [(seq, plaintext), ...]."""
        c = self._contacts.get(peer_id)
        if c is None:
            raise MailboxError("no such contact")
        mailbox = derive_mailbox(c.pair_secret, sender=peer_id, recipient=self.my_id, epoch=epoch)
        out: List[Tuple[int, bytes]] = []
        for blob in self._relay.fetch(mailbox):
            opened = open_message(c.pair_secret, SealedEnvelope(mailbox, blob), epoch=epoch)
            if opened is not None:
                _sender, seq, pt = opened
                out.append((seq, pt))
        return out

    def receive_window(self, peer_id: bytes, *, now_round: int, window: int) -> List[Tuple[int, bytes]]:
        """Catch-up receive: poll the rotating mailbox across the last `window` beacon rounds so a
        recipient who was offline — or whose clock skews a round or two from the sender's — still
        finds every message. Returns [(seq, plaintext), ...] de-duplicated by seq. A blob sealed at
        round R only opens under round R's mailbox+key, so scanning other rounds finds nothing there
        (no double counting); the dedup is a belt-and-suspenders guard."""
        c = self._contacts.get(peer_id)
        if c is None:
            raise MailboxError("no such contact")
        seen: set = set()
        out: List[Tuple[int, bytes]] = []
        for epoch in catch_up_epochs(now_round, window=window):
            mailbox = derive_mailbox(c.pair_secret, sender=peer_id, recipient=self.my_id, epoch=epoch)
            for blob in self._relay.fetch(mailbox):
                opened = open_message(c.pair_secret, SealedEnvelope(mailbox, blob), epoch=epoch)
                if opened is not None:
                    _sender, seq, pt = opened
                    if seq not in seen:
                        seen.add(seq)
                        out.append((seq, pt))
        return out
