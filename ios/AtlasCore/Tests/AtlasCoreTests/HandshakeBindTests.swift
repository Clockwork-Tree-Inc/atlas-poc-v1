import XCTest
@testable import AtlasCore

/// Mirrors backend/tests/test_handshake_bind.py.
final class HandshakeBindTests: XCTestCase {

    func testDetectTapsFindsImpulses() {
        var sig = [Double](repeating: 0.02, count: 200)
        for idx in [50, 100, 150] { sig[idx] = 3.0 }
        let taps = detectTaps(sig, fs: 100.0, threshold: 1.0)
        XCTAssertEqual(taps.count, 3)
        XCTAssertLessThan(abs(taps[0] - 0.5), 0.02)
        XCTAssertLessThan(abs(taps[2] - 1.5), 0.02)
    }

    func testValidHandshakeBinds() {
        XCTAssertTrue(verifyHandshake(phoneTaps: [9.6, 9.9, 10.2, 10.5],
                                      ringTaps: [9.61, 9.9, 10.19, 10.51],
                                      requestedN: 4, faceIDAtS: 10.0))
    }

    func testWrongCountFails() {
        XCTAssertFalse(verifyHandshake(phoneTaps: [9.7, 10.0, 10.3], ringTaps: [9.7, 10.0, 10.3],
                                       requestedN: 4, faceIDAtS: 10.0))
    }

    func testMisalignedRingFails() {
        XCTAssertFalse(verifyHandshake(phoneTaps: [9.6, 9.9, 10.2, 10.5],
                                       ringTaps: [9.6, 9.9, 10.2, 12.0],   // last tap off
                                       requestedN: 4, faceIDAtS: 10.0))
    }

    func testOutsideFaceIDWindowFails() {
        XCTAssertFalse(verifyHandshake(phoneTaps: [0.6, 0.9, 1.2, 1.5], ringTaps: [0.6, 0.9, 1.2, 1.5],
                                       requestedN: 4, faceIDAtS: 100.0, windowS: 6.0))
    }

    func testMicCorroboration() {
        let phone = [9.7, 10.0, 10.3], ring = [9.71, 10.0, 10.29]
        XCTAssertTrue(verifyHandshake(phoneTaps: phone, ringTaps: ring, requestedN: 3,
                                      faceIDAtS: 10.0, micTaps: [9.7, 10.0, 10.3]))
        XCTAssertFalse(verifyHandshake(phoneTaps: phone, ringTaps: ring, requestedN: 3,
                                       faceIDAtS: 10.0, micTaps: [9.7, 10.0]))   // mic missed one
    }
}
