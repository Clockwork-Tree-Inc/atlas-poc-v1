import XCTest
@testable import AtlasCore

/// Parity with backend/tests/test_trust_publish.py.
final class TrustPublishTests: XCTestCase {
    private func kp(_ n: UInt8) -> HybridSign.Keypair { try! HybridSign.keypair(fromSeed: Data(repeating: n, count: 32)) }

    func testOrgPublishesItsOwnAccreditationAndAVerifierLoadsIt() throws {
        let gov = kp(1), board = kp(2), uni = kp(3)
        let auth = try TrustGraph.authorize(gov, grantee: board.publicKey, remit: TrustGraph.accreditor, grantorName: "DoE")
        let acc = try TrustGraph.accredit(board, org: uni.publicKey, kind: "university", authorityName: "Board")

        let boardBundle = try TrustPublish.buildTrustBundle(publisher: board, domain: "board.example", edges: [auth, acc])
        let uniBundle = try TrustPublish.buildTrustBundle(publisher: uni, domain: "uni.example", edges: [acc])

        let served: [String: Data] = [
            TrustPublish.trustBundleURL("board.example"): boardBundle.toJSON(),
            TrustPublish.trustBundleURL("uni.example"): uniBundle.toJSON(),
        ]
        func fetch(_ u: String) -> Data { served[u]! }

        let g = TrustGraph(trustedRoots: [gov.publicKey.encode()], now: 10)
        try TrustPublish.fetchAndLoad(g, domain: "board.example", fetch: fetch)
        try TrustPublish.fetchAndLoad(g, domain: "uni.example", fetch: fetch)

        XCTAssertNotNil(g.verifyOrg(uni.publicKey, kind: "university"))
    }

    func testBundleRoundTripsThroughJSON() throws {
        let gov = kp(1), board = kp(2)
        let auth = try TrustGraph.authorize(gov, grantee: board.publicKey, remit: TrustGraph.accreditor)
        let b = try TrustPublish.buildTrustBundle(publisher: board, domain: "board.example", edges: [auth])
        let again = try TrustPublish.parseTrustBundle(b.toJSON())
        XCTAssertTrue(TrustPublish.verifyTrustBundle(again))
        XCTAssertEqual(again.domain, "board.example")
        XCTAssertEqual(again.edges[0].claim, auth.claim)
        XCTAssertEqual(again.publisher.encode(), board.publicKey.encode())
    }

    func testTamperedBundleFailsVerification() throws {
        let gov = kp(1), board = kp(2)
        let auth = try TrustGraph.authorize(gov, grantee: board.publicKey, remit: TrustGraph.accreditor)
        let b = try TrustPublish.buildTrustBundle(publisher: board, domain: "board.example", edges: [auth])
        var d = try TrustPublish.parseTrustBundle(b.toJSON())
        d = TrustPublish.TrustBundle(domain: "evil.example", publisher: d.publisher, edges: d.edges, sig: d.sig)
        XCTAssertFalse(TrustPublish.verifyTrustBundle(d))
    }

    func testPublisherCannotBundleEdgesNotAboutIt() throws {
        let board = kp(2), other = kp(9), someUni = kp(3)
        let acc = try TrustGraph.accredit(board, org: someUni.publicKey, kind: "university")
        XCTAssertThrowsError(try TrustPublish.buildTrustBundle(publisher: other, domain: "other.example", edges: [acc]))
    }

    func testForgedEdgeInBundleRejected() throws {
        let board = kp(2), uni = kp(3)
        var acc = try TrustGraph.accredit(board, org: uni.publicKey, kind: "university")
        acc.sig = Data(repeating: 0, count: acc.sig.count)
        XCTAssertThrowsError(try TrustPublish.buildTrustBundle(publisher: board, domain: "board.example", edges: [acc]))
    }
}
