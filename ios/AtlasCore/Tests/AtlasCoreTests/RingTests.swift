import XCTest
@testable import AtlasCore

/// R10 ring wired as the coherent-biology liveness anchor. Mirrors
/// `backend/tests/test_ring.py`, with byte-exact parity vectors from the reference.
final class RingTests: XCTestCase {

    private func fixedLiveWindow() -> [SensorSample] {
        [45.0, 33.0, 57.0, 40.0, 50.0, 38.0, 44.0, 52.0].map {
            SensorSample(hr: 68.0, hrvMS: $0, spo2: 98.0, accelMag: 0.02)
        }
    }
    private func flatWindow() -> [SensorSample] {
        (0..<8).map { _ in SensorSample(hr: 72.0, hrvMS: 3.0, spo2: 98.0, accelMag: 0.001) }
    }
    private func liveSampler() -> () -> SensorSample? {
        var it = fixedLiveWindow().makeIterator()
        return { it.next() }
    }

    // -- the ring as a wired SignalSource -------------------------------------

    func testNoSamplerStillDeferred() {
        XCTAssertThrowsError(try RingSignalSource().sample()) { err in
            guard case SignalSourceError.unavailable = err else { return XCTFail("expected unavailable") }
        }
    }

    func testLivePulseIsPresentAndNotSimulated() throws {
        let s = try RingSignalSource(sampler: liveSampler()).sample()
        XCTAssertTrue(s.present)
        XCTAssertFalse(s.simulated)          // the honesty flip: real biology
        XCTAssertEqual(s.kind, "ring")
    }

    func testRemovedOrSpoofedRingFailsClosed() throws {
        XCTAssertFalse(try RingSignalSource(sampler: { nil }).sample().present)   // removed
        var it = flatWindow().makeIterator()
        XCTAssertFalse(try RingSignalSource(sampler: { it.next() }).sample().present)  // flat HRV spoof
    }

    func testIMUCatchesMotionlessRingWithPlausiblePulse() throws {
        // good pulse but ZERO motion (removed / on a table / replayed pulse) -> fail-closed
        let still = SensorSample(hr: 68.0, hrvMS: 45.0, spo2: 98.0, accelMag: 0.001)
        XCTAssertFalse(try RingSignalSource(sampler: { still }).sample().present)
        let worn = SensorSample(hr: 68.0, hrvMS: 45.0, spo2: 98.0, accelMag: 0.02)
        XCTAssertTrue(try RingSignalSource(sampler: { worn }).sample().present)
    }

    func testRingTimingParity() throws {
        // timing = int(hrvMS*3 + hr) % 256; hrv=45, hr=68 -> 203
        let s = try RingSignalSource(sampler: {
            SensorSample(hr: 68.0, hrvMS: 45.0, spo2: 98.0, accelMag: 0.02)
        }).sample()
        XCTAssertEqual(Array(s.timing), [203])
    }

    // -- the ring populates GBSS h_i (parity vectors) -------------------------

    func testRingHIParity() {
        XCTAssertEqual(GBSS.ringHI(fixedLiveWindow()), 0.95928, accuracy: 1e-4)
        XCTAssertEqual(GBSS.ringHI(flatWindow()), 0.1, accuracy: 1e-4)
        XCTAssertEqual(GBSS.ringHI(Array(fixedLiveWindow().prefix(3))), 0.0)   // too short
    }

    func testRingSIParityAndFusion() {
        // ring_s_i over a fixed accel window (parity vector from the Python reference)
        let w = [0.02, 0.015, 0.028, 0.018, 0.033, 0.012, 0.024, 0.030].map {
            SensorSample(hr: 68.0, hrvMS: 45.0, spo2: 98.0, accelMag: $0)
        }
        XCTAssertEqual(GBSS.ringSI(w), 0.839088, accuracy: 1e-4)
        XCTAssertEqual(GBSS.ringSI(Array(w.prefix(3))), 0.0)                 // too short
        // fusion: ring present -> boosted; absent -> phone's alone
        XCTAssertGreaterThan(GBSS.fuseMotionSI(0.3, ringWindow: w), 0.3)
        XCTAssertEqual(GBSS.fuseMotionSI(0.3, ringWindow: nil), 0.3)
    }

    func testVectorGainsHIWhenRingPresentElseDeferred() {
        let withRing = GBSS.entropyVectorWithRing(sI: 0.7, cI: 0.6, mI: 0.5, ringWindow: fixedLiveWindow())
        XCTAssertFalse(withRing.ringDeferred)
        XCTAssertEqual(Set(withRing.present().keys), ["h_i", "s_i", "m_i", "c_i"])   // all FOUR
        let without = GBSS.entropyVectorWithRing(sI: 0.7, cI: 0.6, ringWindow: nil)
        XCTAssertTrue(without.ringDeferred)
        XCTAssertNil(without.present()["h_i"])
    }
}
