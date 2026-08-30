import XCTest
@testable import AtlasCore

/// On-device accumulator revocation + unlinkable ZK membership (blst). Parity with test_anon_revocation.
final class AnonCredRevocationTests: XCTestCase {
    private func reg(_ seeds: [String]) -> (Revocation.Registry, [Fr]) {
        let r = Revocation.Registry()
        let hs = seeds.map { Revocation.handle(Data($0.utf8)) }
        hs.forEach { r.addMember($0) }
        return (r, hs)
    }

    func testMembershipAndRevocationPublic() {
        let (r, hs) = reg(["a", "b", "c"])
        let acc = r.accumulator()
        for h in hs { XCTAssertTrue(Revocation.verifyMembership(r.pub, acc, handle: h, witness: r.witness(h)!)) }
        let wb = r.witness(hs[1])!
        r.revoke(hs[1])
        XCTAssertFalse(Revocation.verifyMembership(r.pub, r.accumulator(), handle: hs[1], witness: wb))
        XCTAssertNil(r.witness(hs[1]))
        for i in [0, 2] {
            XCTAssertTrue(Revocation.verifyMembership(r.pub, r.accumulator(), handle: hs[i], witness: r.witness(hs[i])!))
        }
    }

    func testZKMembershipCompletenessAndUnlinkability() {
        let (r, hs) = reg(["a", "b"])
        let acc = r.accumulator()
        let p1 = Revocation.proveMembership(r.pub, acc, handle: hs[0], witness: r.witness(hs[0])!, nonce: Data("n".utf8))
        let p2 = Revocation.proveMembership(r.pub, acc, handle: hs[0], witness: r.witness(hs[0])!, nonce: Data("n".utf8))
        XCTAssertTrue(Revocation.verifyMembershipZK(r.pub, acc, p1, nonce: Data("n".utf8)))
        XCTAssertTrue(Revocation.verifyMembershipZK(r.pub, acc, p2, nonce: Data("n".utf8)))
        XCTAssertNotEqual(p1.wbar.serialize(), p2.wbar.serialize())   // re-randomised, unlinkable
        XCTAssertNotEqual(p1.challenge.bytesBE(), p2.challenge.bytesBE())
    }

    func testZKMembershipSoundnessRevokedCannotProve() {
        let (r, hs) = reg(["a", "b"])
        let oldWitness = r.witness(hs[1])!
        r.revoke(hs[1])
        let acc = r.accumulator()
        let bad = Revocation.proveMembership(r.pub, acc, handle: hs[1], witness: oldWitness, nonce: Data("n".utf8))
        XCTAssertFalse(Revocation.verifyMembershipZK(r.pub, acc, bad, nonce: Data("n".utf8)))
        let good = Revocation.proveMembership(r.pub, acc, handle: hs[0], witness: r.witness(hs[0])!, nonce: Data("n".utf8))
        XCTAssertTrue(Revocation.verifyMembershipZK(r.pub, acc, good, nonce: Data("n".utf8)))
    }

    func testZKMembershipNonceBinding() {
        let (r, hs) = reg(["a", "b"])
        let acc = r.accumulator()
        let p = Revocation.proveMembership(r.pub, acc, handle: hs[0], witness: r.witness(hs[0])!, nonce: Data("right".utf8))
        XCTAssertFalse(Revocation.verifyMembershipZK(r.pub, acc, p, nonce: Data("wrong".utf8)))
    }
}
