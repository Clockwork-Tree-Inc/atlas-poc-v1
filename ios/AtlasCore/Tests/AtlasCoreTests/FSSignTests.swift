import XCTest
@testable import AtlasCore

/// Swift forward-secure signer — mirrors backend/tests/test_fs_sign.py. The load-bearing test:
/// after ratcheting, a fully-compromised current state cannot forge a PAST epoch (A13 structural).
final class FSSignTests: XCTestCase {
    let SEED = Data((0..<32).map(UInt8.init))
    let MSG = Data("grant-body-bytes".utf8)

    func testSignVerifyAndAdvance() throws {
        let (pub, s) = try FSSign.keygen(seed: SEED, height: 3)
        for expect in 0..<4 {
            let sig = try s.sign(MSG)
            XCTAssertEqual(sig.epoch, expect)
            XCTAssertTrue(FSSign.verify(pub, MSG, sig))
            try s.advance()
        }
    }

    func testOneEpochManyGrants() throws {
        let (pub, s) = try FSSign.keygen(seed: SEED, height: 3)
        let a = try s.sign(Data("A".utf8)), b = try s.sign(Data("B".utf8))
        XCTAssertTrue(FSSign.verify(pub, Data("A".utf8), a))
        XCTAssertTrue(FSSign.verify(pub, Data("B".utf8), b))
    }

    func testForwardSecurityCannotBackdate() throws {
        let (pub, s) = try FSSign.keygen(seed: SEED, height: 3)
        _ = try s.sign(MSG)                                  // honest epoch 0
        for _ in 0..<3 { try s.advance() }                   // compromise: attacker holds s.state (state_3)
        let leaf3 = try HybridSign.keypair(fromSeed: FSSign.leafSeed(s.state))
        // best forgery: current leaf, but claim epoch 0 with epoch-0's public auth path
        let forged = FSSign.FSSignature(epoch: 0, leafPublic: leaf3.publicKey.encode(),
                                        sig: try HybridSign.sign(leaf3, MSG),
                                        authPath: FSSign.authPath(s.levels, 0))
        XCTAssertFalse(FSSign.verify(pub, MSG, forged))      // REJECTED — leaf/auth-path/root mismatch
    }

    func testTamperedRejected() throws {
        let (pub, s) = try FSSign.keygen(seed: SEED, height: 3)
        let sig = try s.sign(MSG)
        XCTAssertFalse(FSSign.verify(pub, Data("other".utf8), sig))    // wrong message
        let wrongEpoch = FSSign.FSSignature(epoch: 1, leafPublic: sig.leafPublic, sig: sig.sig, authPath: sig.authPath)
        XCTAssertFalse(FSSign.verify(pub, MSG, wrongEpoch))            // wrong epoch -> root mismatch
    }
}
