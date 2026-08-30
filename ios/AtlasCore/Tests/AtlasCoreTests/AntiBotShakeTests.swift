import XCTest
@testable import AtlasCore

/// Shake-to-prove-human: RNG-derived plan + escalating lock. These KATs are the
/// byte-parity contract with `backend/tests/test_antibot.py` — the same nonce
/// must yield the same plan, digest, and lock schedule in both implementations.
final class AntiBotShakeTests: XCTestCase {
    private func hex(_ s: String) -> Data {
        var d = Data(); var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            d.append(UInt8(s[i..<j], radix: 16)!); i = j
        }
        return d
    }

    func testShakePlanKnownAnswer() {
        let nonce = hex("000102030405060708090a0b0c0d0e0f")
        let plan = AntiBot.deriveShakePlan(nonce: nonce)          // defaults: 2 segments, 3..6
        XCTAssertEqual(plan, [
            AntiBot.ShakeSegment(direction: AntiBot.sideways, count: 4),
            AntiBot.ShakeSegment(direction: AntiBot.upDown, count: 5),
        ])
        XCTAssertEqual(AntiBot.shakePlanDigest(plan).map { String(format: "%02x", $0) }.joined(),
                       "54a3d6e3d176d7e2fa8389e0020b4adcb9fe55fc5e1d78e267b70a11de5ce0a7")
    }

    func testShakePlanDeterministicAndNonceSensitive() {
        let n = hex("000102030405060708090a0b0c0d0e0f")
        XCTAssertEqual(AntiBot.deriveShakePlan(nonce: n), AntiBot.deriveShakePlan(nonce: n))
        XCTAssertNotEqual(AntiBot.deriveShakePlan(nonce: Data(repeating: 0, count: 16)),
                          AntiBot.deriveShakePlan(nonce: Data(repeating: 1, count: 16)))
    }

    func testShakePlanRangeAndDirections() {
        let plan = AntiBot.deriveShakePlan(nonce: hex("000102030405060708090a0b0c0d0e0f"),
                                           segments: 3, minCount: 3, maxCount: 6)
        XCTAssertEqual(plan.count, 3)
        for seg in plan {
            XCTAssertTrue(seg.direction == AntiBot.upDown || seg.direction == AntiBot.sideways)
            XCTAssertTrue(seg.count >= 3 && seg.count <= 6)
        }
    }

    func testLockBackoffSchedule() {
        for n in 0...AntiBot.lockFreeTries { XCTAssertEqual(AntiBot.lockBackoffSeconds(failCount: n), 0) }
        XCTAssertEqual(AntiBot.lockBackoffSeconds(failCount: 11), 30)
        XCTAssertEqual(AntiBot.lockBackoffSeconds(failCount: 12), 60)
        XCTAssertEqual(AntiBot.lockBackoffSeconds(failCount: 13), 120)
        XCTAssertEqual(AntiBot.lockBackoffSeconds(failCount: 14), 240)
        XCTAssertEqual(AntiBot.lockBackoffSeconds(failCount: 100), 3600)
    }
}

extension AntiBotShakeTests {
    /// Tap-plan parity with the Python reference (same nonce -> same rhythm + digest).
    func testTapPlanKATMatchesPython() {
        let nonce = Data((0..<16).map { UInt8($0) })
        let plan = AntiBot.deriveTapPlan(nonce: nonce)
        XCTAssertEqual(plan.map { $0.count }, [3, 3])
        XCTAssertEqual(AntiBot.tapPlanDigest(plan).map { String(format: "%02x", $0) }.joined(),
                       "71d7e8bda3347a4221f9e77e5f7a0798c5d846ed055c65bbdf0150f3ba480bef")
        for seg in AntiBot.deriveTapPlan(nonce: Data(repeating: 0xff, count: 16),
                                         segments: 5, minTaps: 1, maxTaps: 9) {
            XCTAssertTrue((1...9).contains(seg.count))
        }
    }
}
