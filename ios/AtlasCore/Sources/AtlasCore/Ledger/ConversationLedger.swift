import Foundation

/// Per-conversation ledger choice (TRUST_LAYER.md #9). Mirrors
/// `backend/atlas/ledger/conversation.py`. Reuses the existing `ConversationMode`:
/// ACCOUNTABLE commits each message + anchors the root (selectively provable later); DENIABLE
/// commits nothing (AEAD-only, deniable transcript).
public enum ConversationLedger {

    /// ACCOUNTABLE conversations are ledger-anchored; DENIABLE ones are not.
    public static func isAnchoredMode(_ mode: ConversationMode) -> Bool { mode == .accountable }

    /// The author's private receipt for one anchored message. `opening` is the secret kept to
    /// prove this message later; `commitment` is what the ledger holds.
    public struct AnchoredMessage {
        public let commitment: Data
        public let opening: Data
        public let index: Int
    }

    /// A selective-disclosure proof: reveals ONE message's content + opening and its Merkle
    /// inclusion against a (globally anchored) root. Reveals nothing about other messages.
    public struct MessageProof {
        public let content: Data
        public let opening: Data
        public let inclusion: InclusionProof
        public func verify() -> Bool {
            let (expected, _) = LedgerCommit.commit(content, opening: opening)
            return expected == inclusion.commitment && inclusion.verify()
        }
    }

    /// Record a message per the conversation's mode. ACCOUNTABLE -> commit + append, returning
    /// the author's receipt. DENIABLE -> nil (nothing committed; the transcript is deniable).
    public static func recordMessage(_ ledger: IndividualLedger, mode: ConversationMode,
                                     content: Data) -> AnchoredMessage? {
        guard isAnchoredMode(mode) else { return nil }
        let (commitment, opening) = LedgerCommit.commit(content)
        let index = ledger.append(commitment)
        return AnchoredMessage(commitment: commitment, opening: opening, index: index)
    }

    /// Build a proof that `content` (this author's anchored message) is in `ledger`, against
    /// its current root. The verifier separately checks that root was globally anchored.
    public static func proveMessage(_ ledger: IndividualLedger, msg: AnchoredMessage,
                                    content: Data) -> MessageProof {
        MessageProof(content: content, opening: msg.opening, inclusion: ledger.prove(msg.index))
    }
}
