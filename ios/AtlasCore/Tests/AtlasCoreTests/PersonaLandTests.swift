import XCTest
@testable import AtlasCore

/// A persona's hosting "land" (`Spaces.PersonaLand`) — the "host anything digital" primitive.
/// Verifies: any opaque bytes host successfully (content-agnostic), the land is deterministic
/// per persona (re-derivable) yet unlinkable across personas, only the owner may host, and
/// PUBLIC hosting anchors to the global log.
final class PersonaLandTests: XCTestCase {

    private func seed(_ b: UInt8) -> Data { Data(repeating: b, count: 32) }
    private let spaceID = Data("alice-land".utf8)
    private let vaultID = Data("alice-vault".utf8)

    func testCreateLandForProfile() throws {
        let tree = try IdentityTree.build(tskSeed: Primitives.randomBytes(32), sphincs: StubSphincs())
        let shop = try tree.profile("shop")
        let anon = try tree.profile("anon")
        let landShop = try Spaces.createLand(for: shop)
        let landAnon = try Spaces.createLand(for: anon)
        // per-persona, unlinkable across personas
        XCTAssertNotEqual(landShop.space.spaceID, landAnon.space.spaceID)
        XCTAssertNotEqual(landShop.authorHandle, landAnon.authorHandle)
        // deterministic per persona (re-derivable)
        XCTAssertEqual(try Spaces.createLand(for: tree.profile("shop")).space.spaceID, landShop.space.spaceID)
        // hosting works through the convenience
        let item = try landShop.host(Data("hello".utf8), now: 1)
        XCTAssertEqual(landShop.hosted(now: 1).map { $0.contentHash }, [item.contentHash])
    }

    func testHostsAnyDigitalArtifact() throws {
        let land = try Spaces.createLand(personaSeed: seed(1), spaceID: spaceID, vaultID: vaultID)
        XCTAssertEqual(land.space.vaultID, vaultID)              // land lives in the persona's vault

        // arbitrary "digital things" — all just bytes
        let img = try land.host(Data([0x89, 0x50, 0x4e, 0x47]), now: 1)   // PNG header
        let doc = try land.host(Data("hello.md".utf8), now: 2)
        let app = try land.host(Data(repeating: 0xAB, count: 4096), now: 3)  // an "app bundle"
        XCTAssertEqual(Set(land.hosted(now: 3).map { $0.contentHash }),
                       Set([img.contentHash, doc.contentHash, app.contentHash]))
        XCTAssertNotEqual(img.contentHash, doc.contentHash)     // distinct commitments
    }

    func testLandIsDeterministicPerPersonaAndUnlinkable() throws {
        let a1 = try Spaces.createLand(personaSeed: seed(1), spaceID: spaceID, vaultID: vaultID)
        let a2 = try Spaces.createLand(personaSeed: seed(1), spaceID: spaceID, vaultID: vaultID)
        let b = try Spaces.createLand(personaSeed: seed(2), spaceID: spaceID, vaultID: vaultID)
        XCTAssertEqual(a1.authorHandle, a2.authorHandle)        // same persona re-derives its land
        XCTAssertEqual(a1.space.ownerRoot.root, a2.space.ownerRoot.root)
        XCTAssertNotEqual(a1.authorHandle, b.authorHandle)      // different personas -> unlinkable lands
        XCTAssertNotEqual(a1.space.ownerRoot.root, b.space.ownerRoot.root)
    }

    func testOnlyOwnerMayHost() throws {
        let land = try Spaces.createLand(personaSeed: seed(1), spaceID: spaceID, vaultID: vaultID)
        // a non-owner (empty grant chain) cannot post to the SELF land (fail-closed)
        XCTAssertThrowsError(try land.store.post(authorChain: [], author: Data("intruder".utf8),
                                                 content: Data("x".utf8), now: 1))
    }

    func testPublicHostingAnchorsGlobally() throws {
        let log = GlobalAnchor.Log()
        let land = try Spaces.createLand(personaSeed: seed(1), spaceID: spaceID, vaultID: vaultID,
                                         persistence: .publicMode, globalAnchor: log)
        _ = try land.host(Data("published".utf8), now: 100)
        XCTAssertTrue(land.store.isPubliclyProvable(), "PUBLIC-hosted content anchors to the global log")
        XCTAssertTrue(log.verifyChain())
    }
}
