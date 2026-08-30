import XCTest
@testable import AtlasCore

/// On-device master-secret accreditation (blst). Parity with test_anon_accreditation.
final class AnonCredTests: XCTestCase {
    private func kp(_ n: UInt8) -> HybridSign.Keypair { try! HybridSign.keypair(fromSeed: Data(repeating: n, count: 32)) }

    func testDisplayFromAnyPersonaAnonymously() {
        let issuer = AnonCred.newIssuer()
        let ms = AnonCred.masterSecret(Data("my-root".utf8))
        let cred = AnonCred.issue(issuer, claim: "work:BSc", master: ms)
        let p = AnonCred.present(issuer.pub, cred, claim: "work:BSc", master: ms, nonce: Data("n".utf8))
        XCTAssertTrue(AnonCred.verify(issuer.pub, p, claim: "work:BSc", nonce: Data("n".utf8)))
        // wrong master secret can't present
        let bad = AnonCred.present(issuer.pub, cred, claim: "work:BSc", master: AnonCred.masterSecret(Data("other".utf8)), nonce: Data("n".utf8))
        XCTAssertFalse(AnonCred.verify(issuer.pub, bad, claim: "work:BSc", nonce: Data("n".utf8)))
    }

    func testClaimUnderARealIDAndHijackRejected() throws {
        let academy = AnonCred.newIssuer()
        let ms = AnonCred.masterSecret(Data("root".utf8))
        let award = AnonCred.issue(academy, claim: "award:LitPrize", master: ms)
        let realID = kp(1), attacker = kp(2)
        let (proof, ident, link) = try AnonCred.presentLinked(academy.pub, award, claim: "award:LitPrize",
                                                              master: ms, nonce: Data("n".utf8), identity: realID)
        XCTAssertEqual(ident.encode(), realID.publicKey.encode())
        XCTAssertTrue(AnonCred.verifyLinked(academy.pub, proof, claim: "award:LitPrize", nonce: Data("n".utf8),
                                            identity: realID.publicKey, linkSig: link))
        // an onlooker can't re-attribute the award to themselves
        XCTAssertFalse(AnonCred.verifyLinked(academy.pub, proof, claim: "award:LitPrize", nonce: Data("n".utf8),
                                             identity: attacker.publicKey, linkSig: link))
    }
}
