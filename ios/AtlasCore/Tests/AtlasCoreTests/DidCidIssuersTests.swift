import XCTest
@testable import AtlasCore

final class DidCidTests: XCTestCase {
    private func kp(_ n: UInt8) -> HybridSign.Keypair { try! HybridSign.keypair(fromSeed: Data(repeating: n, count: 32)) }

    func testFormatAndDeterminism() {
        let d = DidCid.didFor(kp(1).publicKey)
        XCTAssertTrue(d.hasPrefix("did:cid:f"))
        XCTAssertEqual(d, DidCid.didFor(kp(1).publicKey))
    }
    func testDifferentKeysDifferentDids() {
        XCTAssertNotEqual(DidCid.didFor(kp(1).publicKey), DidCid.didFor(kp(2).publicKey))
    }
    func testOrderIndependent() {
        let a = kp(1).publicKey, b = kp(2).publicKey
        XCTAssertEqual(DidCid.didCid([a, b]), DidCid.didCid([b, a]))
    }
    func testSelfCertifying() {
        let d = DidCid.didFor(kp(1).publicKey)
        XCTAssertTrue(DidCid.verifyDid(d, keys: [kp(1).publicKey]))
        XCTAssertFalse(DidCid.verifyDid(d, keys: [kp(2).publicKey]))
    }
}

final class IssuersTests: XCTestCase {
    private func kp(_ n: UInt8) -> HybridSign.Keypair { try! HybridSign.keypair(fromSeed: Data(repeating: n, count: 32)) }
    private func profile(_ n: UInt8, _ ec: EntityClass = .individual) -> ParticipantProfile {
        ParticipantProfile(handle: Data(repeating: n, count: 32), publicKey: kp(n).publicKey, entityClass: ec)
    }

    func testIssuedRealIDSatisfiesSupplyGate() throws {
        let verifier = Issuers.Issuer(kp(1), name: "Verifier")
        let seller = profile(2)
        try seller.hold(try verifier.issueRealID(subject: seller.handle))
        XCTAssertTrue(try SupplyGate.canPerform(seller, action: "sell",
                                                trustedVerifierKeys: [verifier.publicKey.encode()]))
    }

    func testOrgNeedsRealIDAndRegistration() throws {
        let verifier = Issuers.Issuer(kp(1), name: "Verifier")
        let registry = Issuers.Issuer(kp(3), name: "Registry")
        let org = profile(2, .forProfit)
        let vkeys = Set([verifier.publicKey.encode()]); let rkeys = Set([registry.publicKey.encode()])
        try org.hold(try verifier.issueRealID(subject: org.handle))
        XCTAssertFalse(try SupplyGate.canPerform(org, action: "sell", trustedVerifierKeys: vkeys, trustedRegistryKeys: rkeys))
        try org.hold(try registry.issueRegistration(subject: org.handle))
        XCTAssertTrue(try SupplyGate.canPerform(org, action: "sell", trustedVerifierKeys: vkeys, trustedRegistryKeys: rkeys))
    }

    func testCategoryClaim() throws {
        let body = Issuers.Issuer(kp(5), name: "Health Registry")
        let att = try body.issueCategory(subject: Data(repeating: 9, count: 32), sector: "healthcare")
        XCTAssertEqual(att.claim, "category:healthcare")
    }

    func testValidCredentialTrustAndRevocation() throws {
        let issuer = Issuers.Issuer(kp(1), name: "Verifier")
        let att = try issuer.issueRealID(subject: Data(repeating: 2, count: 32))
        XCTAssertTrue(Issuers.validCredential(att, trustedIssuerKeys: [issuer.publicKey.encode()]))
        XCTAssertFalse(Issuers.validCredential(att, trustedIssuerKeys: [kp(9).publicKey.encode()]))

        issuer.revoke(att)
        XCTAssertTrue(issuer.isRevoked(att))
        XCTAssertFalse(Issuers.validCredential(att, trustedIssuerKeys: [issuer.publicKey.encode()],
                                               revoked: issuer.revocationSet))
    }
}
