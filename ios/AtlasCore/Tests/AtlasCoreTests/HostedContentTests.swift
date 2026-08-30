import XCTest
@testable import AtlasCore

/// Serving layer (2a) client core — `Spaces.sealHosted`/`openHosted`. Verifies node-blind sealing
/// (ciphertext only), seal→open roundtrip, and that tampering / wrong key / substituted plaintext
/// are all rejected; plus the tie-in to `PersonaLand` (a hosted item's commitment equals its
/// sealed blob's commitment, so fetch-and-verify closes the loop).
final class HostedContentTests: XCTestCase {

    private let spaceID = Data("space-1".utf8)
    private let author = Data("author-h".utf8)
    private let key = Data(repeating: 0x2b, count: 32)

    func testSealIsNodeBlindAndRoundtrips() throws {
        let content = Data("a secret document".utf8)
        let (blob, commitment) = try Spaces.sealHosted(content: content, sealKey: key,
                                                       spaceID: spaceID, author: author)
        // node-blind: it stores ciphertext addressed by H(ciphertext), never the plaintext
        XCTAssertNotEqual(blob.ciphertext, content)
        XCTAssertEqual(blob.blobID, Primitives.H(Data("atlas/hosted-blob".utf8), blob.ciphertext))
        // a holder of the key recovers it and it verifies against the land commitment
        let back = try Spaces.openHosted(blob, sealKey: key, expectCommitment: commitment,
                                         spaceID: spaceID, author: author)
        XCTAssertEqual(back, content)
    }

    func testTamperWrongKeyAndSubstitutionRejected() throws {
        let (blob, commitment) = try Spaces.sealHosted(content: Data("x".utf8), sealKey: key,
                                                       spaceID: spaceID, author: author)
        // tampered ciphertext -> address no longer matches
        var bad = blob; bad = Spaces.HostedBlob(blobID: blob.blobID, ciphertext: Data(blob.ciphertext.reversed()))
        XCTAssertThrowsError(try Spaces.openHosted(bad, sealKey: key, expectCommitment: commitment,
                                                   spaceID: spaceID, author: author)) {
            XCTAssertEqual($0 as? Spaces.HostError, .corruptBlob)
        }
        // wrong key -> AEAD fails
        XCTAssertThrowsError(try Spaces.openHosted(blob, sealKey: Data(repeating: 9, count: 32),
                                                   expectCommitment: commitment, spaceID: spaceID, author: author)) {
            XCTAssertEqual($0 as? Spaces.HostError, .wrongKey)
        }
        // right key but wrong expected commitment (a substituted/forged reference) -> rejected
        XCTAssertThrowsError(try Spaces.openHosted(blob, sealKey: key, expectCommitment: Data(repeating: 0, count: 32),
                                                   spaceID: spaceID, author: author)) {
            XCTAssertEqual($0 as? Spaces.HostError, .commitmentMismatch)
        }
    }

    /// The hosted item in a persona's land and its sealed servable blob agree on the commitment —
    /// so a fetcher verifies served bytes against what the land recorded.
    func testHostedItemMatchesSealedBlob() throws {
        let land = try Spaces.createLand(personaSeed: Data(repeating: 1, count: 32),
                                         spaceID: Data("alice-land".utf8), vaultID: Data("alice-vault".utf8))
        let content = Data("my hosted app".utf8)
        let item = try land.host(content, now: 1)
        let (blob, commitment) = try Spaces.sealHosted(content: content, sealKey: key,
                                                       spaceID: land.space.spaceID, author: land.authorHandle)
        XCTAssertEqual(commitment, item.contentHash, "the land item and its servable blob share the commitment")
        let served = try Spaces.openHosted(blob, sealKey: key, expectCommitment: item.contentHash,
                                           spaceID: land.space.spaceID, author: land.authorHandle)
        XCTAssertEqual(served, content)
    }
}
