import XCTest
@testable import AtlasCore

/// Space content store (`Spaces.SpaceStore`), ported from `backend/atlas/spaces/content.py`.
/// Verifies content-commitment parity with Python, the persistence-mode dispatch
/// (PRESENT/FADING/PRIVATE/PUBLIC), threading (replies), PUBLIC global-anchoring, and the
/// moderator-gated ban (which rides the authority engine end-to-end).
final class ContentTests: XCTestCase {

    private func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
    private let spaceID = Data("space-1".utf8)

    private func openSpace(_ anchor: Bool = false) throws -> (Spaces.SpaceStore, GlobalAnchor.Log?) {
        let (root, _) = try FSSign.keygen(seed: Data(repeating: 3, count: 32), height: 3)
        let space = Spaces.makeSpace(spaceID, kind: .commons, ownerRoot: root,
                                     persistence: .privateMode, access: .open, identity: .anonymous)
        let log = anchor ? GlobalAnchor.Log() : nil
        return (Spaces.SpaceStore(space: space, globalAnchor: log), log)
    }

    func testContentCommitmentMatchesPython() {
        XCTAssertEqual(hex(Spaces.contentCommitment(spaceID: Data("space-1".utf8),
                                                    author: Data("author-h".utf8),
                                                    content: Data("hello world".utf8))),
                       "218c5187554fb566e130a64d2fc26a08743039d60847987e7354782bfbc31ac2")
        XCTAssertEqual(hex(Spaces.contentCommitment(spaceID: Data("space-1".utf8),
                                                    author: Data("author-h".utf8),
                                                    content: Data("a reply".utf8),
                                                    parent: Data("PARENT".utf8))),
                       "d6cd7cb4c198d668ae2c274f794817c95e95f21dd8beed6522d6e604bc5631fd")
    }

    func testPersistenceModesAndThreading() throws {
        let (store, _) = try openSpace()
        let author = Data("alice".utf8)
        // PRESENT — nothing stored.
        _ = try store.post(authorChain: [], author: author, content: Data("ephemeral".utf8), now: 1,
                           persistence: .present)
        XCTAssertTrue(store.live(now: 1).isEmpty)
        // PRIVATE (default) top-level post + a threaded reply.
        let post = try store.post(authorChain: [], author: author, content: Data("top".utf8), now: 2)
        let reply = try store.post(authorChain: [], author: author, content: Data("re".utf8), now: 3,
                                   parent: post.contentHash)
        XCTAssertEqual(store.replies(parent: post.contentHash).map { $0.contentHash }, [reply.contentHash])
        // FADING — pruned past expiry.
        _ = try store.post(authorChain: [], author: author, content: Data("temp".utf8), now: 10,
                           persistence: .fading, ttl: 5)
        XCTAssertEqual(store.live(now: 12).filter { $0.persistence == .fading }.count, 1)  // alive at 12
        XCTAssertTrue(store.live(now: 20).allSatisfy { $0.persistence != .fading })         // pruned at 20
    }

    func testPublicPersistenceAnchorsGlobally() throws {
        let (store, log) = try openSpace(true)
        XCTAssertFalse(store.isPubliclyProvable())
        _ = try store.post(authorChain: [], author: Data("alice".utf8), content: Data("public".utf8),
                           now: 100, persistence: .publicMode)
        XCTAssertTrue(store.isPubliclyProvable(), "a PUBLIC post anchors the ledger root to the global log")
        XCTAssertTrue(log!.verifyChain())
    }

    /// Moderation rides the authority engine: a MODERATOR+ grant lets you ban; a non-mod can't;
    /// a banned author can no longer post to the OPEN space.
    func testModeratorGatedBan() throws {
        let (root, signer) = try FSSign.keygen(seed: Data(repeating: 3, count: 32), height: 3)
        let space = Spaces.makeSpace(spaceID, kind: .commons, ownerRoot: root,
                                     persistence: .privateMode, access: .open, identity: .anonymous)
        let store = Spaces.SpaceStore(space: space)

        let mod = try HybridSign.keypair(fromSeed: Data(repeating: 9, count: 32))
        let modGrant = try Authority.issueFS(signer, grantee: mod.publicKey, resource: spaceID,
                                             rights: Authority.RightSet(Spaces.Role.moderator.rawValue))
        let bad = Data("troll".utf8)

        // a non-moderator (empty chain) cannot ban
        XCTAssertThrowsError(try store.ban(modChain: [], target: bad, now: 1))
        // the moderator can
        _ = try store.ban(modChain: [modGrant], target: bad, now: 1)
        // and the banned author can no longer post
        XCTAssertThrowsError(try store.post(authorChain: [], author: bad, content: Data("spam".utf8), now: 2)) {
            XCTAssertEqual($0 as? Spaces.ContentError, .access("author is banned from this space"))
        }
        // a different author still posts fine
        XCTAssertNoThrow(try store.post(authorChain: [], author: Data("ok".utf8), content: Data("hi".utf8), now: 3))
    }
}
