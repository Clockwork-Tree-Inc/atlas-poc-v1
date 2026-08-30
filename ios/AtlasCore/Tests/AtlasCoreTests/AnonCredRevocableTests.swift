import XCTest
@testable import AtlasCore

/// On-device revocable anonymous credential (blst). Parity with test_anon_revocable.
final class AnonCredRevocableTests: XCTestCase {
    private func setup(handleSeed: String = "h-a") -> (PS.SecretKey, Revocation.Registry, Fr, Fr, PS.Signature) {
        let issuer = Revocable.newIssuer()
        let reg = Revocation.Registry()
        let master = Fr.msg("my-root")
        let handle = Revocation.handle(Data(handleSeed.utf8))
        reg.addMember(handle)
        let cred = Revocable.issue(issuer, claim: "work:BSc", master: master, handle: handle)
        return (issuer, reg, master, handle, cred)
    }

    func testValidAndNonrevokedVerifies() {
        let (issuer, reg, master, handle, cred) = setup()
        let acc = reg.accumulator()
        let p = Revocable.present(issuer.pub, cred, accPub: reg.pub, accumulator: acc,
                                  claim: "work:BSc", master: master, handle: handle, witness: reg.witness(handle)!, nonce: Data("n".utf8))
        XCTAssertTrue(Revocable.verify(issuer.pub, accPub: reg.pub, accumulator: acc, p, claim: "work:BSc", nonce: Data("n".utf8)))
    }

    func testRevokedFails() {
        let (issuer, reg, master, handle, cred) = setup()
        reg.addMember(Revocation.handle(Data("other".utf8)))
        let oldWitness = reg.witness(handle)!
        reg.revoke(handle)
        let acc = reg.accumulator()
        let p = Revocable.present(issuer.pub, cred, accPub: reg.pub, accumulator: acc,
                                  claim: "work:BSc", master: master, handle: handle, witness: oldWitness, nonce: Data("n".utf8))
        XCTAssertFalse(Revocable.verify(issuer.pub, accPub: reg.pub, accumulator: acc, p, claim: "work:BSc", nonce: Data("n".utf8)))
    }

    func testCannotBorrowAnotherHandleAndWitness() {
        let (issuer, reg, master, _, cred) = setup()
        let other = Revocation.handle(Data("other".utf8))
        reg.addMember(other)
        let acc = reg.accumulator()
        // present with `other`'s (valid, non-revoked) handle+witness but MY credential -> must fail
        let p = Revocable.present(issuer.pub, cred, accPub: reg.pub, accumulator: acc,
                                  claim: "work:BSc", master: master, handle: other, witness: reg.witness(other)!, nonce: Data("n".utf8))
        XCTAssertFalse(Revocable.verify(issuer.pub, accPub: reg.pub, accumulator: acc, p, claim: "work:BSc", nonce: Data("n".utf8)))
    }

    func testUnlinkableAndWrongClaimFails() {
        let (issuer, reg, master, handle, cred) = setup()
        let acc = reg.accumulator()
        let p1 = Revocable.present(issuer.pub, cred, accPub: reg.pub, accumulator: acc,
                                   claim: "work:BSc", master: master, handle: handle, witness: reg.witness(handle)!, nonce: Data("n".utf8))
        let p2 = Revocable.present(issuer.pub, cred, accPub: reg.pub, accumulator: acc,
                                   claim: "work:BSc", master: master, handle: handle, witness: reg.witness(handle)!, nonce: Data("n".utf8))
        XCTAssertTrue(Revocable.verify(issuer.pub, accPub: reg.pub, accumulator: acc, p1, claim: "work:BSc", nonce: Data("n".utf8)))
        XCTAssertNotEqual(p1.s1.serialize(), p2.s1.serialize())
        XCTAssertNotEqual(p1.wbar.serialize(), p2.wbar.serialize())
        XCTAssertFalse(Revocable.verify(issuer.pub, accPub: reg.pub, accumulator: acc, p1, claim: "work:PhD", nonce: Data("n".utf8)))
    }
}
