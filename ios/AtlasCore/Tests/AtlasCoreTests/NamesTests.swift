import XCTest
@testable import AtlasCore

/// Naming/discovery registry (Swift), parity with `backend/atlas/names.py`.
final class NamesTests: XCTestCase {
    private func identity(_ n: String) throws -> Child {
        try IdentityTree.build(tskSeed: Primitives.randomBytes(32), sphincs: StubSphincs()).profile(n).identity
    }

    func testClaimBodyParityKAT() {
        // byte-identical to the Python reference `_claim_body("coolshop", bytes(32), 0)`
        let hex = Names.claimBody(name: "coolshop", handle: Data(count: 32), epoch: 0)
            .map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(hex, "ed596212c0ed599585395786747d541fef242beeba1a1e76420c9230422d0aeb")
    }

    func testClaimResolveAndUniqueness() throws {
        let shop = try identity("shop")
        let reg = Names.NameRegistry()
        let c = try Names.claimName(shop, name: "coolshop")
        XCTAssertTrue(Names.verifyClaim(c))
        try reg.register(c)
        XCTAssertEqual(reg.resolve("coolshop"), shop.handle)
        XCTAssertThrowsError(try reg.register(try Names.claimName(try identity("other"), name: "coolshop")))
        try reg.register(try Names.claimName(shop, name: "coolshop", epoch: 1))   // same handle refresh ok
        XCTAssertEqual(reg.resolve("coolshop"), shop.handle)
        XCTAssertNil(reg.resolve("unclaimed"))
    }

    func testCannotNameAHandleYouDontControl() throws {
        let victim = try identity("victim")
        let attacker = try identity("atk")
        var forged = Names.NameClaim(name: "victimname", handle: victim.handle,
                                     publicKey: attacker.publicKey, epoch: 0)
        forged.sig = try HybridSign.sign(attacker.keypair,
                                         Names.claimBody(name: "victimname", handle: victim.handle, epoch: 0))
        XCTAssertFalse(Names.verifyClaim(forged))
    }

    func testReleaseAndRevoke() throws {
        let p = try identity("p")
        let reg = Names.NameRegistry()
        try reg.register(try Names.claimName(p, name: "freed"))
        reg.release(p, "freed")
        XCTAssertNil(reg.resolve("freed"))
        let q = try identity("q")
        try reg.register(try Names.claimName(q, name: "freed"))
        XCTAssertEqual(reg.resolve("freed"), q.handle)
        reg.revoke("freed")
        XCTAssertNil(reg.resolve("freed"))
        XCTAssertThrowsError(try reg.register(try Names.claimName(q, name: "freed")))
    }
}
