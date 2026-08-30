import XCTest
@testable import AtlasCore

/// Parity with backend/tests/test_trust_graph.py.
final class TrustGraphTests: XCTestCase {
    private func kp(_ n: UInt8) -> HybridSign.Keypair { try! HybridSign.keypair(fromSeed: Data(repeating: n, count: 32)) }
    private func graph(_ roots: HybridSign.Keypair..., now: Int = 10) -> TrustGraph {
        TrustGraph(trustedRoots: Set(roots.map { $0.publicKey.encode() }), now: now)
    }

    func testAccreditorAuthorizedByRootVerifiesOrg() throws {
        let gov = kp(1), board = kp(2), uni = kp(3)
        let g = graph(gov)
        try g.add(TrustGraph.authorize(gov, grantee: board.publicKey, remit: TrustGraph.accreditor, grantorName: "DoE"))
        try g.add(TrustGraph.accredit(board, org: uni.publicKey, kind: "university", authorityName: "Regional Board"))
        let path = g.verifyOrg(uni.publicKey, kind: "university")
        XCTAssertNotNil(path)
        XCTAssertEqual(path?.authorities(), ["DoE", "Regional Board"])
    }

    func testUnauthorizedAccreditorDoesNotVerifyOrg() throws {
        let gov = kp(1), imposter = kp(2), uni = kp(3)
        let g = graph(gov)
        try g.add(TrustGraph.accredit(imposter, org: uni.publicKey, kind: "university", authorityName: "Totally Legit"))
        XCTAssertNil(g.verifyOrg(uni.publicKey))
    }

    func testDownstreamAccreditationFlowsThroughMultipleHops() throws {
        let gov = kp(1), national = kp(2), regional = kp(3), uni = kp(4)
        let g = graph(gov)
        try g.add(TrustGraph.authorize(gov, grantee: national.publicKey, remit: TrustGraph.accreditor))
        try g.add(TrustGraph.authorize(national, grantee: regional.publicKey, remit: TrustGraph.accreditor))
        try g.add(TrustGraph.accredit(regional, org: uni.publicKey, kind: "university"))
        XCTAssertNotNil(g.verifyOrg(uni.publicKey))

        let registry = kp(5), other = kp(6)
        try g.add(TrustGraph.authorize(gov, grantee: registry.publicKey, remit: TrustGraph.registry))
        try g.add(TrustGraph.accredit(registry, org: other.publicKey, kind: "university"))
        XCTAssertNil(g.verifyOrg(other.publicKey))   // registry remit can't accredit
    }

    func testPersonBoundToRealWorldIdentity() throws {
        let verifier = kp(1), alice = kp(7)
        let g = graph()
        try g.add(TrustGraph.bindRealIdentity(verifier, person: alice.publicKey, verifierName: "eID"))
        XCTAssertTrue(g.hasRealIdentity(alice.publicKey, trustedVerifierKeys: [verifier.publicKey.encode()]))
        XCTAssertFalse(g.hasRealIdentity(alice.publicKey, trustedVerifierKeys: [kp(99).publicKey.encode()]))
    }

    func testAccreditedSchoolCertifiesItsGraduate() throws {
        let gov = kp(1), board = kp(2), uni = kp(3), doctor = kp(8)
        let g = graph(gov)
        try g.add(TrustGraph.authorize(gov, grantee: board.publicKey, remit: TrustGraph.accreditor))
        try g.add(TrustGraph.accredit(board, org: uni.publicKey, kind: "university"))
        try g.add(TrustGraph.certify(uni, person: doctor.publicKey, qualification: "md", issuerName: "Central College"))
        XCTAssertNotNil(g.verifyQualification(doctor.publicKey, "md"))

        let fake = kp(50), quack = kp(51)
        try g.add(TrustGraph.certify(fake, person: quack.publicKey, qualification: "md"))
        XCTAssertNil(g.verifyQualification(quack.publicKey, "md"))
    }

    func testLicensorCanCertifyAPersonDirectly() throws {
        let gov = kp(1), medboard = kp(2), doctor = kp(8)
        let g = graph(gov)
        try g.add(TrustGraph.authorize(gov, grantee: medboard.publicKey, remit: TrustGraph.licensor))
        try g.add(TrustGraph.certify(medboard, person: doctor.publicKey, qualification: "md", issuerName: "Council"))
        XCTAssertNotNil(g.verifyQualification(doctor.publicKey, "md"))
    }

    func testCrossRecognitionAcrossTwoRoots() throws {
        let usGov = kp(1), ukGov = kp(10)
        let g = graph(usGov, ukGov)
        for (gov, board, uni, doc) in [(usGov, kp(2), kp(3), kp(8)), (ukGov, kp(11), kp(12), kp(13))] {
            try g.add(TrustGraph.authorize(gov, grantee: board.publicKey, remit: TrustGraph.accreditor))
            try g.add(TrustGraph.accredit(board, org: uni.publicKey, kind: "university"))
            try g.add(TrustGraph.certify(uni, person: doc.publicKey, qualification: "md"))
        }
        XCTAssertNotNil(g.verifyQualification(kp(8).publicKey, "md"))
        XCTAssertNotNil(g.verifyQualification(kp(13).publicKey, "md"))
    }

    func testAffiliationRequiresAVerifiedOrg() throws {
        let gov = kp(1), board = kp(2), uni = kp(3), registrar = kp(9)
        let g = graph(gov)
        try g.add(TrustGraph.affiliate(uni, person: registrar.publicKey, role: "registrar", orgName: "Central College"))
        XCTAssertNil(g.verifyAffiliation(registrar.publicKey, org: uni.publicKey, role: "registrar"))
        try g.add(TrustGraph.authorize(gov, grantee: board.publicKey, remit: TrustGraph.accreditor))
        try g.add(TrustGraph.accredit(board, org: uni.publicKey, kind: "university"))
        XCTAssertNotNil(g.verifyAffiliation(registrar.publicKey, org: uni.publicKey, role: "registrar"))
    }

    func testRegistrationByNumberAndDuplicateDetection() throws {
        let gov = kp(1), registry = kp(2), mine = kp(3), imposter = kp(4)
        let g = graph(gov)
        try g.add(TrustGraph.authorize(gov, grantee: registry.publicKey, remit: TrustGraph.registry))
        try g.add(TrustGraph.register(registry, org: mine.publicKey, number: "OC-12345", registryName: "Companies House"))
        XCTAssertNotNil(g.verifyOrg(mine.publicKey))
        XCTAssertTrue(g.soleRegistrant(mine.publicKey, "OC-12345"))
        XCTAssertFalse(g.registrationConflict("OC-12345"))

        try g.add(TrustGraph.register(registry, org: imposter.publicKey, number: "OC-12345"))
        XCTAssertTrue(g.registrationConflict("OC-12345"))
        XCTAssertFalse(g.soleRegistrant(mine.publicKey, "OC-12345"))
    }

    func testRevocationForwardEffective() throws {
        let gov = kp(1), board = kp(2), uni = kp(3)
        let g = graph(gov)
        try g.add(TrustGraph.authorize(gov, grantee: board.publicKey, remit: TrustGraph.accreditor))
        let acc = try TrustGraph.accredit(board, org: uni.publicKey, kind: "university")
        try g.add(acc)
        XCTAssertNotNil(g.verifyOrg(uni.publicKey))
        g.revoke(acc)
        XCTAssertNil(g.verifyOrg(uni.publicKey))
    }

    func testForgedEdgeRejectedAtAdd() throws {
        let gov = kp(1), board = kp(2), uni = kp(3)
        let g = graph(gov)
        var acc = try TrustGraph.accredit(board, org: uni.publicKey, kind: "university")
        acc.sig = Data(repeating: 0, count: acc.sig.count)
        XCTAssertThrowsError(try g.add(acc))
    }

    func testFutureDatedEdgeNotYetLive() throws {
        let gov = kp(1), board = kp(2), uni = kp(3)
        let g = graph(gov, now: 5)
        try g.add(TrustGraph.authorize(gov, grantee: board.publicKey, remit: TrustGraph.accreditor, epoch: 1))
        try g.add(TrustGraph.accredit(board, org: uni.publicKey, kind: "university", epoch: 9))
        XCTAssertNil(g.verifyOrg(uni.publicKey))
        g.now = 10
        XCTAssertNotNil(g.verifyOrg(uni.publicKey))
    }
}
