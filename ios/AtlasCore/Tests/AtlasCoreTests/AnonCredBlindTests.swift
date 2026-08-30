import XCTest
@testable import AtlasCore

/// On-device PS blind issuance (blst). Parity with test_anon_accreditation's blind-pickup tests.
final class AnonCredBlindTests: XCTestCase {
    func testBlindPickupHidesTheSecretAndCredentialVerifies() throws {
        let sk = PS.keygen(2)                       // [claim, master_secret]
        let claim = Fr.msg("work:BSc")
        let master = Fr.msg("my-root")
        // holder commits, hiding master (index 1); issuer sees only the claim
        let (req, t) = PS.blindRequest(sk.pub, hidden: [1: master])
        let blinded = try PS.blindSign(sk, req, disclosed: [0: claim])
        let cred = PS.blindUnblind(blinded, blinding: t)
        // the finalized credential presents + verifies like a normal one
        let proof = PS.present(sk.pub, cred, messages: [claim, master], reveal: [0], nonce: Data("n".utf8))
        XCTAssertTrue(PS.verify(sk.pub, proof, nonce: Data("n".utf8)))
    }

    func testBlindlyIssuedCredentialBoundToRealSecret() throws {
        let sk = PS.keygen(2)
        let claim = Fr.msg("work:BSc"), master = Fr.msg("root")
        let (req, t) = PS.blindRequest(sk.pub, hidden: [1: master])
        let cred = PS.blindUnblind(try PS.blindSign(sk, req, disclosed: [0: claim]), blinding: t)
        // presenting with a DIFFERENT secret must fail
        let wrong = Fr.msg("different-root")
        let bad = PS.present(sk.pub, cred, messages: [claim, wrong], reveal: [0], nonce: Data("n".utf8))
        XCTAssertFalse(PS.verify(sk.pub, bad, nonce: Data("n".utf8)))
    }

    func testForgedCommitmentProofRejected() throws {
        let sk = PS.keygen(2)
        let (req, _) = PS.blindRequest(sk.pub, hidden: [1: Fr.msg("root")])
        let forged = PS.BlindRequest(C: req.C, hiddenIdx: req.hiddenIdx,
                                     challenge: req.challenge, responses: req.responses.map { _ in Fr.zero })
        XCTAssertThrowsError(try PS.blindSign(sk, forged, disclosed: [0: Fr.msg("work:BSc")]))
    }
}
