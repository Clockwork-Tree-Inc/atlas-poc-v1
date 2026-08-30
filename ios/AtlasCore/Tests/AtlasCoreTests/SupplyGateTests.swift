import XCTest
@testable import AtlasCore

final class SupplyGateTests: XCTestCase {
    private func kp(_ n: UInt8) -> HybridSign.Keypair { try! HybridSign.keypair(fromSeed: Data(repeating: n, count: 32)) }
    private func profile(_ n: UInt8, _ ec: EntityClass = .individual) -> (HybridSign.Keypair, ParticipantProfile) {
        let k = kp(n)
        return (k, ParticipantProfile(handle: Data(repeating: n, count: 32), publicKey: k.publicKey, entityClass: ec))
    }
    private func give(_ p: ParticipantProfile, _ authority: HybridSign.Keypair, _ claim: String) throws {
        let att = try issueAttestation(authority: authority, authorityName: "Verifier", subject: p.handle, claim: claim)
        try p.hold(att)
    }

    func testAnyoneCanBuyAnonymously() throws {
        let (_, buyer) = profile(2)
        XCTAssertTrue(try SupplyGate.canPerform(buyer, action: "buy"))
        XCTAssertTrue(try SupplyGate.canPerform(buyer, action: "browse"))
        XCTAssertFalse(try SupplyGate.canPerform(buyer, action: "sell"))
    }

    func testIndividualWithTrustedRealIDCanSell() throws {
        let verifier = kp(1)
        let (_, seller) = profile(2)
        try give(seller, verifier, SupplyGate.realIDClaim)
        XCTAssertTrue(try SupplyGate.canPerform(seller, action: "sell", trustedVerifierKeys: [verifier.publicKey.encode()]))
        XCTAssertTrue(try SupplyGate.canPerform(seller, action: "earn", trustedVerifierKeys: [verifier.publicKey.encode()]))
    }

    func testUntrustedVerifierDoesNotCount() throws {
        let verifier = kp(1), other = kp(9)
        let (_, seller) = profile(2)
        try give(seller, verifier, SupplyGate.realIDClaim)
        XCTAssertFalse(try SupplyGate.canPerform(seller, action: "sell", trustedVerifierKeys: [other.publicKey.encode()]))
    }

    func testOrganizationNeedsRealIDAndRegistration() throws {
        let verifier = kp(1), registry = kp(3)
        let (_, org) = profile(2, .forProfit)
        try give(org, verifier, SupplyGate.realIDClaim)
        let vkeys = Set([verifier.publicKey.encode()]); let rkeys = Set([registry.publicKey.encode()])
        XCTAssertFalse(try SupplyGate.canPerform(org, action: "sell", trustedVerifierKeys: vkeys, trustedRegistryKeys: rkeys))
        try give(org, registry, SupplyGate.registrationClaim)
        XCTAssertTrue(try SupplyGate.canPerform(org, action: "sell", trustedVerifierKeys: vkeys, trustedRegistryKeys: rkeys))
    }

    func testNonprofitIsAnOrganizationForTheGate() throws {
        let verifier = kp(1), registry = kp(3)
        let (_, org) = profile(2, .nonprofit)
        try give(org, verifier, SupplyGate.realIDClaim)
        XCTAssertFalse(try SupplyGate.canPerform(org, action: "provide",
                                                 trustedVerifierKeys: [verifier.publicKey.encode()],
                                                 trustedRegistryKeys: [registry.publicKey.encode()]))
    }

    func testAgentNeverDirectSupplyActor() throws {
        let verifier = kp(1)
        let (_, agent) = profile(2, .agent)
        try give(agent, verifier, SupplyGate.realIDClaim)
        XCTAssertFalse(try SupplyGate.canPerform(agent, action: "sell", trustedVerifierKeys: [verifier.publicKey.encode()]))
        XCTAssertTrue(try SupplyGate.canPerform(agent, action: "buy"))
    }

    func testUnknownActionThrows() {
        let (_, p) = profile(2)
        XCTAssertThrowsError(try SupplyGate.canPerform(p, action: "teleport"))
    }
}
