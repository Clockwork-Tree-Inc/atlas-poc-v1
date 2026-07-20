"""Per-decision forensic ledger — every login / high-stakes decision leaves a
vault-sealed, tamper-evident, signed forensic event, and those events are the substrate
that detects suspicious activity.

This complements the two pieces already in the tree:
  * `session/forensic.py` — the ALARM-triggered capture WINDOW (bursts on panic /
    improper disconnect / suspicious lifecycle). That's the "something happened, capture
    it" path.
  * `liveness/attestation.py` — flags `SUSPICIOUS` on a liveness break.

This module is the AUDIT TRAIL: a decision log. Every decision (allow / deny / escalate)
is recorded as a `ForensicEvent`:
  * HASH-CHAINED (prev_hash) — dropping, reordering, or altering any event breaks the
    chain at verification (same tamper-evidence as the forensic window).
  * SIGNED by the device/enclave key — a forged event does not verify.
  * SEALED into the vault (AEAD) — opaque at rest; the sensitive context is not readable
    without the holder's vault key.

`assess_risk` classifies the current signals — sudden liveness loss, strange login
attempts (new device, impossible travel, off-hours, repeated failed factors), duress,
total loss — into a `RiskLevel` that drives escalation. Routine -> allow; anything
suspicious/duress/emergency -> escalate. The decision AND its risk are recorded, so the
log both audits and feeds the next assessment.

INVARIANT: the ledger GATES/audits and TIMES; it never enters key material. Risk is a
policy signal, not entropy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import List, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ..crypto.primitives import H, aead_decrypt, aead_encrypt

GENESIS = b"\x00" * 32


# --------------------------------------------------------------------------- enums
class DecisionType(Enum):
    LOGIN = "login"
    HIGH_STAKES = "high-stakes"
    RECOVERY = "recovery"
    PAYMENT = "payment"


class Outcome(Enum):
    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"


class RiskLevel(IntEnum):
    ROUTINE = 0
    SUSPICIOUS = 1
    DURESS = 2
    EMERGENCY = 3


# --------------------------------------------------------------------------- signals
@dataclass(frozen=True)
class Signals:
    """The context of one decision. `sudden_liveness_loss` is a mid-session liveness
    break (attestation SUSPICIOUS); the rest are "strange login" heuristics."""

    factors_ok: bool = True          # the required factors were satisfied
    liveness_present: bool = True
    sudden_liveness_loss: bool = False
    known_device: bool = True
    impossible_travel: bool = False   # geovelocity anomaly
    off_hours: bool = False
    recent_failures: int = 0          # failed factor attempts in the recent window
    duress: bool = False
    total_loss: bool = False


def assess_risk(sig: Signals, *, failure_threshold: int = 3) -> RiskLevel:
    """Classify the decision's risk. Highest applicable level wins (fail-closed toward
    escalation)."""
    if sig.duress:
        return RiskLevel.DURESS
    if sig.total_loss:
        return RiskLevel.EMERGENCY
    if (sig.sudden_liveness_loss or sig.impossible_travel or not sig.known_device
            or sig.recent_failures >= failure_threshold):
        return RiskLevel.SUSPICIOUS
    return RiskLevel.ROUTINE


def decide_outcome(sig: Signals, risk: RiskLevel) -> Outcome:
    """The decision itself: factors must pass, and any elevated risk escalates rather
    than silently allowing."""
    if not sig.factors_ok:
        return Outcome.DENY
    if risk >= RiskLevel.SUSPICIOUS:
        return Outcome.ESCALATE
    return Outcome.ALLOW


# --------------------------------------------------------------------------- event
def _lp(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


def _pack(seq: int, prev_hash: bytes, drand_round: bytes, decision: DecisionType,
          outcome: Outcome, risk: RiskLevel, context_handle: bytes,
          signal_digest: bytes) -> bytes:
    return b"".join([
        seq.to_bytes(8, "big"), _lp(prev_hash), _lp(drand_round),
        _lp(decision.value.encode()), _lp(outcome.value.encode()),
        risk.to_bytes(1, "big"), _lp(context_handle), _lp(signal_digest),
    ])


def _signal_digest(sig: Signals) -> bytes:
    return H(b"atlas/forensic/signals",
             bytes([sig.factors_ok, sig.liveness_present, sig.sudden_liveness_loss,
                    sig.known_device, sig.impossible_travel, sig.off_hours,
                    sig.duress, sig.total_loss]),
             sig.recent_failures.to_bytes(4, "big"))


@dataclass(frozen=True)
class ForensicEvent:
    """The plaintext decision record. `context_handle` is a pseudonym/handle for the
    subject — never the digital-you System-ID directly, preserving unlinkability."""

    seq: int
    prev_hash: bytes
    drand_round: bytes
    decision: DecisionType
    outcome: Outcome
    risk: RiskLevel
    context_handle: bytes
    signal_digest: bytes

    def event_hash(self) -> bytes:
        return H(b"atlas/forensic/event",
                 _pack(self.seq, self.prev_hash, self.drand_round, self.decision,
                       self.outcome, self.risk, self.context_handle, self.signal_digest))


@dataclass
class SealedEntry:
    """One ledger row. The chain-anchoring hashes + signature are in the clear (they
    reveal nothing); the event itself is sealed (opaque at rest)."""

    seq: int
    prev_hash: bytes
    event_hash: bytes
    signature: bytes          # Ed25519 over event_hash
    sealed: bytes             # AEAD(packed event) under the vault key


# --------------------------------------------------------------------------- ledger
class ForensicLedger:
    """Append-only, hash-chained, signed, vault-sealed decision log. Construct with the
    device signing key (authenticity) and the vault key (sealing). `record` appends one
    event per decision; `verify` re-checks the whole chain."""

    def __init__(self, device_key: Ed25519PrivateKey, vault_key: bytes) -> None:
        self._device = device_key
        self._vault_key = vault_key
        self._head = GENESIS
        self.entries: List[SealedEntry] = []

    @property
    def device_public(self) -> bytes:
        return self._device.public_key().public_bytes_raw()

    def record(self, *, decision: DecisionType, outcome: Outcome, risk: RiskLevel,
               drand_round: bytes, context_handle: bytes, signals: Signals) -> ForensicEvent:
        event = ForensicEvent(
            seq=len(self.entries), prev_hash=self._head, drand_round=drand_round,
            decision=decision, outcome=outcome, risk=risk,
            context_handle=context_handle, signal_digest=_signal_digest(signals))
        eh = event.event_hash()
        packed = _pack(event.seq, event.prev_hash, event.drand_round, event.decision,
                       event.outcome, event.risk, event.context_handle, event.signal_digest)
        entry = SealedEntry(
            seq=event.seq, prev_hash=event.prev_hash, event_hash=eh,
            signature=self._device.sign(eh),
            sealed=aead_encrypt(self._vault_key, packed, aad=eh))
        self.entries.append(entry)
        self._head = eh
        return event

    def verify(self, *, device_public: Optional[bytes] = None) -> bool:
        """Re-derive the chain: every prev_hash links, every signature verifies, and the
        sealed content still hashes to the recorded event_hash. Any tamper -> False."""
        pub = Ed25519PublicKey.from_public_bytes(device_public or self.device_public)
        head = GENESIS
        for i, e in enumerate(self.entries):
            if e.seq != i or e.prev_hash != head:
                return False
            try:
                pub.verify(e.signature, e.event_hash)
                packed = aead_decrypt(self._vault_key, e.sealed, aad=e.event_hash)
            except Exception:
                return False
            if H(b"atlas/forensic/event", packed) != e.event_hash:
                return False
            head = e.event_hash
        return True


# --------------------------------------------------------------------------- one-call decision
@dataclass
class Decision:
    outcome: Outcome
    risk: RiskLevel
    event: ForensicEvent


def decide_and_record(ledger: ForensicLedger, *, decision: DecisionType,
                      drand_round: bytes, context_handle: bytes, signals: Signals,
                      failure_threshold: int = 3) -> Decision:
    """The integration point: assess risk, make the decision, and RECORD it — so no
    login / high-stakes decision happens without a vault forensic event."""
    risk = assess_risk(signals, failure_threshold=failure_threshold)
    outcome = decide_outcome(signals, risk)
    event = ledger.record(decision=decision, outcome=outcome, risk=risk,
                          drand_round=drand_round, context_handle=context_handle, signals=signals)
    return Decision(outcome=outcome, risk=risk, event=event)
