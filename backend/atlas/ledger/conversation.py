"""Per-conversation ledger choice (TRUST_LAYER.md #9).

When you start a conversation you choose whether it is secured on a ledger. This reuses the
existing per-chat `ConversationMode`:

  * ACCOUNTABLE -> each message's COMMITMENT (never its content) is appended to the owner's
    individual ledger; the root is anchored globally (see `global_anchor`). "Who said what" is
    selectively provable LATER by revealing one `(content, opening)` + its Merkle inclusion.
  * DENIABLE -> nothing is committed; AEAD-only, so the transcript stays deniable.

This gives linkability where you want it and unlinkability where you want it, at conversation
granularity — mutual and visible (the mode is chosen up front), commitments-not-content, and
provable only later, at the author's discretion.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..session.conversation import ConversationMode
from .individual import IndividualLedger, InclusionProof, commit


def is_anchored_mode(mode: ConversationMode) -> bool:
    """ACCOUNTABLE conversations are ledger-anchored; DENIABLE ones are not."""
    return mode is ConversationMode.ACCOUNTABLE


@dataclass(frozen=True)
class AnchoredMessage:
    """The author's private receipt for one anchored message. `opening` is the secret the
    author keeps to prove this message later; `commitment` is what the ledger holds."""

    commitment: bytes
    opening: bytes
    index: int


@dataclass(frozen=True)
class MessageProof:
    """A selective-disclosure proof: reveals ONE message's content + opening and its Merkle
    inclusion against a (globally anchored) root. Reveals nothing about other messages."""

    content: bytes
    opening: bytes
    inclusion: InclusionProof

    def verify(self) -> bool:
        expected, _ = commit(self.content, self.opening)
        return expected == self.inclusion.commitment and self.inclusion.verify()


def record_message(ledger: IndividualLedger, mode: ConversationMode,
                   content: bytes) -> Optional[AnchoredMessage]:
    """Record a message per the conversation's mode. ACCOUNTABLE -> commit + append to the
    ledger, returning the author's receipt. DENIABLE -> return None (nothing committed; the
    content stays off any ledger and the transcript is deniable)."""
    if not is_anchored_mode(mode):
        return None
    commitment, opening = commit(content)
    index = ledger.append(commitment)
    return AnchoredMessage(commitment=commitment, opening=opening, index=index)


def prove_message(ledger: IndividualLedger, msg: AnchoredMessage, content: bytes) -> MessageProof:
    """Build a proof that `content` (this author's anchored message) is in `ledger`, against
    its current root. The verifier separately checks that root was globally anchored."""
    return MessageProof(content=content, opening=msg.opening,
                        inclusion=ledger.prove(msg.index))
