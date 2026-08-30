import XCTest
@testable import AtlasCore

/// Parity with backend/tests/test_address.py.
final class AddressTests: XCTestCase {
    private func kp(_ n: UInt8) -> HybridSign.Keypair { try! HybridSign.keypair(fromSeed: Data(repeating: n, count: 32)) }

    func testParseAndFormatAddress() throws {
        let a = try Address.parse("ada@example.town")
        XCTAssertEqual(a.local, "ada")
        XCTAssertEqual(a.place, "example.town")
        XCTAssertEqual(a.string, "ada@example.town")
        XCTAssertEqual(Address.nameplateURL(a), "https://example.town/.well-known/atlas/ada.json")
        for bad in ["noatsign", "a@b@c", "@place", "local@"] {
            XCTAssertThrowsError(try Address.parse(bad))
        }
    }

    func testPublishAndResolveANameplate() throws {
        let persona = kp(1)
        let addr = try Address.parse("ada@example.id")
        let settings = Address.DiscoverySettings(findable: true, receptive: .codeOnly)
        let np = try Address.buildNameplate(persona, address: addr, displayName: "Ada Rivera", settings: settings)!
        let served = [Address.nameplateURL(addr): np.toJSON()]
        let got = try Address.resolve("ada@example.id", fetch: { served[$0]! })
        XCTAssertEqual(got.key.encode(), persona.publicKey.encode())
        XCTAssertEqual(got.displayName, "Ada Rivera")
        XCTAssertEqual(got.receptive, .codeOnly)
    }

    func testUnfindablePersonaPublishesNoNameplate() throws {
        let persona = kp(1)
        let addr = try Address.parse("ghost@example.id")
        let np = try Address.buildNameplate(persona, address: addr, displayName: "",
                                            settings: Address.DiscoverySettings(findable: false, receptive: .open))
        XCTAssertNil(np)
    }

    func testHostCannotForgeANameplate() throws {
        let persona = kp(1), attacker = kp(2)
        let addr = try Address.parse("ada@example.id")
        var np = try Address.buildNameplate(persona, address: addr, displayName: "Ada Rivera",
                                            settings: Address.DiscoverySettings(findable: true, receptive: .open))!
        np = Address.Nameplate(local: np.local, place: np.place, key: attacker.publicKey,
                               displayName: np.displayName, receptive: np.receptive, sig: np.sig)
        let served = [Address.nameplateURL(addr): np.toJSON()]
        XCTAssertThrowsError(try Address.resolve("ada@example.id", fetch: { served[$0]! }))
    }

    func testNameplateCanCarryTheTrustBundle() throws {
        let persona = kp(1), gov = kp(3)
        let edge = try TrustGraph.authorize(gov, grantee: persona.publicKey, remit: TrustGraph.accreditor)
        let bundle = try TrustPublish.buildTrustBundle(publisher: persona, domain: "example.id", edges: [edge])
        let addr = try Address.parse("ada@example.id")
        let np = try Address.buildNameplate(persona, address: addr, displayName: "Ada Rivera",
                                            settings: Address.DiscoverySettings(findable: true, receptive: .open),
                                            trustBundle: bundle)!
        let served = [Address.nameplateURL(addr): np.toJSON()]
        let got = try Address.resolve("ada@example.id", fetch: { served[$0]! })
        XCTAssertNotNil(got.trustBundle)
        XCTAssertTrue(TrustPublish.verifyTrustBundle(got.trustBundle!))
    }

    func testFindableAndReceptiveAreIndependent() {
        let s1 = Address.DiscoverySettings(findable: true, receptive: .closed)
        XCTAssertFalse(s1.acceptsContact(hasValidCode: true, isKnownContact: true))
        let s2 = Address.DiscoverySettings(findable: false, receptive: .codeOnly)
        XCTAssertTrue(s2.acceptsContact(hasValidCode: true, isKnownContact: false))
        XCTAssertFalse(s2.acceptsContact(hasValidCode: false, isKnownContact: false))
        let s3 = Address.DiscoverySettings(findable: true, receptive: .contactsOnly)
        XCTAssertTrue(s3.acceptsContact(hasValidCode: false, isKnownContact: true))
        XCTAssertFalse(s3.acceptsContact(hasValidCode: true, isKnownContact: false))
    }

    func testPrivateRoutingManyAddressesOneInbox() {
        let work = kp(4), personal = kp(5)
        let inbox = Data(repeating: 0x11, count: 16)
        let rt = Address.RoutingTable()
        rt.point("ada@work.example", persona: work.publicKey)
        rt.point("ada@personal.example", persona: personal.publicKey)
        rt.converge(work.publicKey, inbox: inbox)
        rt.converge(personal.publicKey, inbox: inbox)
        XCTAssertEqual(rt.personaFor("ada@work.example"), work.publicKey.encode())
        XCTAssertEqual(rt.inboxForAddress("ada@work.example"), inbox)
        XCTAssertEqual(rt.inboxForAddress("ada@personal.example"), inbox)
        XCTAssertNil(rt.inboxForAddress("unknown@nowhere.com"))
    }
}
