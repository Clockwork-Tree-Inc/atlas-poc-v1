import XCTest
@testable import AtlasCore

/// Entropy operators + GBSS vector. Mirrors `backend/tests/test_entropy_operators.py`
/// and `test_gbss.py`, with byte-exact parity vectors from the Python reference.
final class EntropyTests: XCTestCase {

    // -- operators (parity vectors) -------------------------------------------

    func testLempelZivParity() {
        let loop = Data(Array(repeating: [UInt8(0x12), UInt8(0x34)], count: 32).flatMap { $0 })
        XCTAssertEqual(Entropy.lempelZivComplexity(loop), 0.105469, accuracy: 1e-5)
        XCTAssertEqual(Entropy.lempelZivComplexity(Data(count: 64)), 0.035156, accuracy: 1e-5)
        XCTAssertEqual(Entropy.lempelZivComplexity(Data((0..<32).map(UInt8.init))), 0.78125, accuracy: 1e-5)
    }

    func testSpectralEntropyParity() {
        let tone = (0..<64).map { sin(2 * Double.pi * 5 * Double($0) / 64) }
        XCTAssertEqual(Entropy.spectralEntropy(tone), 0.0, accuracy: 1e-6)
        let wave = (0..<64).map { Double(($0 * 7) % 13 - 6) }
        XCTAssertEqual(Entropy.spectralEntropy(wave), 0.566275, accuracy: 1e-4)
        XCTAssertEqual(Entropy.spectralEntropy([3.0, 3.0, 3.0, 3.0]), 0.0)   // constant -> 0
    }

    func testShannonAndDistributionBounds() {
        XCTAssertEqual(Entropy.shannonBits(Data()), 0.0)
        XCTAssertEqual(Entropy.shannonBits(Data(repeating: 0, count: 32)), 0.0)
        XCTAssertEqual(Entropy.shannonBits(Data((0...255).map(UInt8.init))), 8.0, accuracy: 1e-9)
        let (sh, mn) = Entropy.distributionEntropies(Array(repeating: [Data("A".utf8), Data("B".utf8)], count: 8).flatMap { $0 })
        XCTAssertEqual(sh, 1.0, accuracy: 1e-9); XCTAssertEqual(mn, 1.0, accuracy: 1e-9)
    }

    func testLempelZivSeparatesLiveFromDegenerate() {
        let random = Entropy.lempelZivComplexity(Primitives.randomBytes(64))
        let loop = Entropy.lempelZivComplexity(Data(Array(repeating: [UInt8(0x12), UInt8(0x34)], count: 32).flatMap { $0 }))
        XCTAssertGreaterThan(random, 0.8)
        XCTAssertGreaterThan(random, loop)
    }

    // -- GBSS vector -----------------------------------------------------------

    func testChannelDensityParity() {
        let loop = Array(repeating: [Data(repeating: 1, count: 8), Data(repeating: 2, count: 8)], count: 8).flatMap { $0 }
        XCTAssertEqual(GBSS.channelDensity(symbols: loop), 0.149414, accuracy: 1e-4)
        XCTAssertEqual(GBSS.channelDensity(waveform: Array(repeating: 3.0, count: 64)), 0.0)
        XCTAssertEqual(GBSS.channelDensity(), 0.0)
    }

    func testEntropyVectorRingDeferredAndDensity() {
        let v = EntropyVector(sI: 0.8, cI: 0.7, mI: 0.6)
        XCTAssertTrue(v.ringDeferred)                                   // h_i absent on phone
        XCTAssertEqual(Set(v.present().keys), ["s_i", "c_i", "m_i"])
        XCTAssertEqual(v.density(), 0.7, accuracy: 1e-9)
        let vr = EntropyVector(sI: 0.8, cI: 0.7, mI: 0.6, hI: 0.9)
        XCTAssertFalse(vr.ringDeferred); XCTAssertNotNil(vr.present()["h_i"])
    }

    func testGBSSLikelihoodsParity() {
        let v = EntropyVector(sI: 0.8, cI: 0.7, mI: 0.6)
        let (live, notLive) = GBSS.livenessLikelihoods(v)
        XCTAssertEqual(live, 0.836, accuracy: 1e-6)
        XCTAssertEqual(notLive, 0.164, accuracy: 1e-6)
        let dead = GBSS.livenessLikelihoods(EntropyVector(sI: 0.05, cI: 0.03))
        XCTAssertLessThan(dead.live, 0.1); XCTAssertGreaterThan(dead.notLive, 0.9)
    }

    func testPoleFromGBSSLiveOperatesDegenerateFailsClosed() {
        let live = Array(repeating: EntropyVector(sI: 0.8, cI: 0.75, mI: 0.7), count: 30)
        XCTAssertTrue(GBSS.poleFromGBSS(live, drandRound: Data(count: 8)).operate)
        let dead = Array(repeating: EntropyVector(sI: 0.04, cI: 0.02), count: 30)
        XCTAssertFalse(GBSS.poleFromGBSS(dead, drandRound: Data(count: 8)).operate)
    }
}
