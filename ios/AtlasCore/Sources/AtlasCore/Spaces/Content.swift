import Foundation

/// Space content + persistence — mirrors `backend/atlas/spaces/content.py`. A post is content by a
/// role-gated author, committed by hash, and witnessed per the space's persistence mode
/// (PRESENT → FADING → PRIVATE → PUBLIC). Composes existing primitives — the authority engine
/// (`hasRole`), `IndividualLedger`, `GlobalAnchor.Log` — no new crypto. Holds commitments +
/// metadata only; content bytes are sealed in the space vault elsewhere.
extension Spaces {

    public enum ContentError: Error, Equatable { case access(String) }

    /// The public commitment to a post: binds space, author handle, content, and (for a reply) the
    /// `parent` it threads under. `parent` empty (default) for a top-level post.
    public static func contentCommitment(spaceID: Data, author: Data, content: Data,
                                         parent: Data = Data()) -> Data {
        Primitives.H(Data("atlas/space-item".utf8), spaceID, author, content, parent)
    }

    /// A moderation record: `target` (a persona handle) barred from an OPEN space. Honored only when
    /// issued by a MODERATOR+ (enforced in `SpaceStore.ban`) — block-list moderation.
    public struct Ban: Equatable {
        public let spaceID: Data
        public let target: Data
        public let epoch: UInt64
    }

    public struct SpaceItem: Equatable {
        public let spaceID: Data
        public let author: Data              // persona handle (opaque)
        public let contentHash: Data
        public let persistence: PersistenceMode
        public let seq: Int
        public let expiry: UInt64?           // set only for FADING
        public let parent: Data?             // content hash of the item this replies to (nil = top-level)
    }

    /// Content store for ONE space. Dispatches by persistence mode over the existing ledgers.
    public final class SpaceStore {
        public let space: SpaceDescriptor
        private let ledger: IndividualLedger
        private let globalAnchor: GlobalAnchor.Log?
        private let isVerifiedHuman: ((Data) -> Bool)?
        private var banned: Set<Data> = []
        private var items: [SpaceItem] = []
        private var seq = 0

        public init(space: SpaceDescriptor, globalAnchor: GlobalAnchor.Log? = nil,
                    isVerifiedHuman: ((Data) -> Bool)? = nil) {
            self.space = space
            self.ledger = IndividualLedger(ownerID: space.spaceID)
            self.globalAnchor = globalAnchor
            self.isVerifiedHuman = isVerifiedHuman
        }

        /// MODERATE an OPEN space by block-list: bar `target`. Authorized only for MODERATOR+
        /// (fail-closed via the authority engine) — a random persona can't ban a rival.
        @discardableResult
        public func ban(modChain: [Authority.Grant], target: Data, now: UInt64, epoch: UInt64 = 0) throws -> Ban {
            guard Spaces.hasRole(space, modChain, atLeast: .moderator, now: now) else {
                throw ContentError.access("banning requires >= MODERATOR")
            }
            banned.insert(target)
            return Ban(spaceID: space.spaceID, target: target, epoch: epoch)
        }

        /// Fail-closed posting gate: ACCESS (who may enter) then IDENTITY (accountability tier).
        private func gate(_ authorChain: [Authority.Grant], _ author: Data, _ now: UInt64) throws {
            switch space.access {
            case .open:
                if banned.contains(author) { throw ContentError.access("author is banned from this space") }
            case .selfOnly:
                if !Spaces.hasRole(space, authorChain, atLeast: .owner, now: now) {
                    throw ContentError.access("SELF space: only the owner may post")
                }
            default: // .invite / .member — allow-list
                if !Spaces.hasRole(space, authorChain, atLeast: .member, now: now) {
                    throw ContentError.access("author needs >= MEMBER to post")
                }
            }
            switch space.identity {
            case .verifiedPerson:
                if isVerifiedHuman == nil || !(isVerifiedHuman!(author)) {
                    throw ContentError.access("this space requires a verified-person identity")
                }
            case .pseudonymous:
                if author.isEmpty { throw ContentError.access("this space requires a pseudonym") }
            case .anonymous:
                break
            }
        }

        /// Author a post — or, when `parent` is another item's content hash, a COMMENT/reply that
        /// threads under it (same gate, same persistence).
        @discardableResult
        public func post(authorChain: [Authority.Grant], author: Data, content: Data, now: UInt64,
                         persistence: PersistenceMode? = nil, ttl: UInt64? = nil,
                         parent: Data? = nil) throws -> SpaceItem {
            try gate(authorChain, author, now)
            let mode = persistence ?? space.persistence
            let commit = Spaces.contentCommitment(spaceID: space.spaceID, author: author,
                                                  content: content, parent: parent ?? Data())
            seq += 1
            let expiry: UInt64? = (mode == .fading && ttl != nil) ? now + ttl! : nil
            let item = SpaceItem(spaceID: space.spaceID, author: author, contentHash: commit,
                                 persistence: mode, seq: seq, expiry: expiry, parent: parent)
            switch mode {
            case .present:
                break                                       // live only — nothing stored
            case .fading:
                items.append(item)                          // stored; pruned in live()
            case .privateMode, .publicMode:
                ledger.append(commit)                       // ledgered between the parties
                items.append(item)
                if mode == .publicMode {
                    guard let anchor = globalAnchor else {
                        throw ContentError.access("PUBLIC persistence requires a global anchor")
                    }
                    var be = now.bigEndian
                    let round = withUnsafeBytes(of: &be) { Data($0) }
                    _ = try anchor.anchor(ownerID: space.spaceID, root: ledger.root, epochRound: round)
                }
            }
            return item
        }

        /// Currently-live items — FADING items past their expiry are pruned.
        public func live(now: UInt64) -> [SpaceItem] {
            items.filter { $0.expiry == nil || now <= $0.expiry! }
        }

        /// The comments/replies threaded directly under `parent` (its content hash), in post order.
        public func replies(parent: Data) -> [SpaceItem] {
            items.filter { $0.parent == parent }
        }

        /// Was the current ledger root anchored to the global log (provable to anyone)?
        public func isPubliclyProvable() -> Bool {
            guard let anchor = globalAnchor else { return false }
            return anchor.isAnchored(ownerID: space.spaceID, root: ledger.root)
        }
    }
}
