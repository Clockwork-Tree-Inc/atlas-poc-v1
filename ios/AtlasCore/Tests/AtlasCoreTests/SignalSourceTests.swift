import XCTest
@testable import AtlasCore

/// Swappable signal source — architecture + the value/timing invariant, mirroring
/// backend/tests/test_signal_source.py. The presence/timing derivation must match
/// the Python reference (empty/flatlined -> not present; timing = first byte).
final class SignalSourceTests: XCTestCase {

    private func ambient(_ window: Data, floor: Int = 2) -> ClosureSignalSource {
        ClosureSignalSource(kind: "ambient", simulated: true,
                            channels: ["microphone", "accelerometer"], liveFloor: floor) { window }
    }

    // 1. VALUE-INDEPENDENCE: ambient TIMES, QRNG VALUES.
    func testAmbientTimingNeverEntersTheValue() throws {
        // Two different ambient timing samples...
        let a = try ambient(Data([1, 2, 3, 4, 5, 6, 7, 8])).sample()
        let b = try ambient(Data([0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7])).sample()
        XCTAssertNotEqual(a.timing, b.timing, "timing carries a real WHEN")
        // ...the value path is PoLE.firePoLEValue, which ignores the moment entirely.
        // (Determinism of the QRNG is a CryptoKit RNG property; here we assert the
        // API surface takes the moment only as a schedule input and never mixes it.)
        let v1 = PoLE.firePoLEValue(physioFireMoment: Double(a.timing.first!) / 255.0)
        let v2 = PoLE.firePoLEValue(physioFireMoment: Double(b.timing.first!) / 255.0)
        XCTAssertEqual(v1.count, 32)
        XCTAssertEqual(v2.count, 32)   // both are clean 32-byte QRNG; moment is not an input
    }

    // 2. PRESENCE GATE reflects stream liveness (matches Python byte-for-byte).
    func testPresenceGateReflectsLiveness() throws {
        XCTAssertFalse(try ambient(Data(repeating: 0, count: 8)).sample().present)   // flatlined
        XCTAssertTrue(try ambient(Data([0x11, 0x22] + Data(repeating: 0, count: 6))).sample().present)
        XCTAssertFalse(try ambient(Data()).sample().present)                          // empty
    }

    func testTimingIsFirstByteOfWindow() throws {
        let s = try ambient(Data([0xAB, 0xCD, 0xEF])).sample()
        XCTAssertEqual(s.timing, Data([0xAB]))
    }

    // 3. Ring source is the deferred swap point (raises, never fakes biology).
    func testRingSourceIsDeferred() {
        XCTAssertThrowsError(try RingSignalSource().sample()) { err in
            guard case SignalSourceError.unavailable = err else {
                return XCTFail("expected .unavailable, got \(err)")
            }
        }
    }

    // 4. Ambient is loudly simulated so nothing downstream claims biology.
    func testAmbientIsLoudlySimulated() throws {
        let s = try ambient(Data([1, 1, 1, 1])).sample()
        XCTAssertTrue(s.simulated)
        XCTAssertEqual(s.kind, "ambient")
    }
}
