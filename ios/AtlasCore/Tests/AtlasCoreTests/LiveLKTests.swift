import XCTest
@testable import AtlasCore

/// Two-device co-derived live LK: unpredictable-to-either, controllable-by-neither.
/// Mirrors `backend/tests/test_live_lk.py`.
final class LiveLKTests: XCTestCase {
    private let epoch = Data(repeating: 0, count: 8)

    func testBothDevicesDeriveSameLKRegardlessOfOrder() throws {
        let a = LiveLK.deviceContribution(), b = LiveLK.deviceContribution()
        let fromA = try LiveLK.coDeriveLK([a, b], drandRound: epoch)   // A holds [a, b]
        let fromB = try LiveLK.coDeriveLK([b, a], drandRound: epoch)   // B holds [b, a]
        XCTAssertEqual(fromA, fromB)                                 // order-independent -> same LK
        XCTAssertEqual(fromA.count, 32)
    }

    func testNeitherContributionEqualsOrRevealsLK() throws {
        let a = LiveLK.deviceContribution(), b = LiveLK.deviceContribution()
        let lk = try LiveLK.coDeriveLK([a, b], drandRound: epoch)
        XCTAssertNotEqual(lk, a); XCTAssertNotEqual(lk, b)          // controllable-by-neither
        let a2 = LiveLK.deviceContribution()
        XCTAssertNotEqual(try LiveLK.coDeriveLK([a2, b], drandRound: epoch), lk)
    }

    func testLKIsEpochBound() throws {
        let a = LiveLK.deviceContribution(), b = LiveLK.deviceContribution()
        let e0 = Data(repeating: 0, count: 8), e1 = Data(repeating: 1, count: 8)
        XCTAssertNotEqual(try LiveLK.coDeriveLK([a, b], drandRound: e0),
                          try LiveLK.coDeriveLK([a, b], drandRound: e1))
    }

    func testSingleContributionIsRefused() {
        XCTAssertThrowsError(try LiveLK.coDeriveLK([LiveLK.deviceContribution()], drandRound: epoch))
    }
}
