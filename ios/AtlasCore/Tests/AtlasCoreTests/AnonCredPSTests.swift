import XCTest
@testable import AtlasCore

/// On-device PS anonymous credential (blst). Mirrors the ps_credential.py self-test.
final class AnonCredPSTests: XCTestCase {
    private func msgs() -> [Fr] { [Fr.msg("atlas-verified"), Fr(fromUInt64: 1), Fr.msg("systemid=deadbeef")] }

    func testSignPresentVerify() {
        let sk = PS.keygen(3)
        let sig = PS.sign(sk, messages: msgs())
        // reveal claim(0)+level(1), hide system-id(2)
        let p1 = PS.present(sk.pub, sig, messages: msgs(), reveal: [0, 1], nonce: Data("n1".utf8))
        XCTAssertTrue(PS.verify(sk.pub, p1, nonce: Data("n1".utf8)))
    }

    func testUnlinkableAndHiding() {
        let sk = PS.keygen(3)
        let m = msgs()
        let sig = PS.sign(sk, messages: m)
        let p1 = PS.present(sk.pub, sig, messages: m, reveal: [0, 1], nonce: Data("n1".utf8))
        let p2 = PS.present(sk.pub, sig, messages: m, reveal: [0, 1], nonce: Data("n2".utf8))
        XCTAssertTrue(PS.verify(sk.pub, p1, nonce: Data("n1".utf8)))
        XCTAssertTrue(PS.verify(sk.pub, p2, nonce: Data("n2".utf8)))
        // two presentations of the same credential are unlinkable
        XCTAssertNotEqual(p1.s1.serialize(), p2.s1.serialize())
        XCTAssertNotEqual(p1.challenge.bytesBE(), p2.challenge.bytesBE())
        // the hidden system-id never appears in the revealed values
        XCTAssertFalse(p1.revealedVals.contains { $0 == m[2] })
    }

    func testNonceBinding() {
        let sk = PS.keygen(3)
        let m = msgs()
        let p = PS.present(sk.pub, PS.sign(sk, messages: m), messages: m, reveal: [0, 1], nonce: Data("right".utf8))
        XCTAssertFalse(PS.verify(sk.pub, p, nonce: Data("wrong".utf8)))
    }

    func testTamperedRevealFails() {
        let sk = PS.keygen(3)
        let m = msgs()
        let p = PS.present(sk.pub, PS.sign(sk, messages: m), messages: m, reveal: [0, 1], nonce: Data("n".utf8))
        let bad = PS.Proof(s1: p.s1, s2: p.s2, commitment: p.commitment, reveal: p.reveal,
                           revealedVals: [p.revealedVals[0], Fr(fromUInt64: 9)],
                           responses: p.responses, challenge: p.challenge)
        XCTAssertFalse(PS.verify(sk.pub, bad, nonce: Data("n".utf8)))
    }

    func testWrongIssuerKeyFails() {
        let sk = PS.keygen(3), other = PS.keygen(3)
        let m = msgs()
        let p = PS.present(sk.pub, PS.sign(sk, messages: m), messages: m, reveal: [0, 1], nonce: Data("n".utf8))
        XCTAssertFalse(PS.verify(other.pub, p, nonce: Data("n".utf8)))
    }
}
