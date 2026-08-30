import XCTest
@testable import AtlasCore

/// Parity with backend/atlas/session/presence_unlock.py — MAX held only while presence is fresh.
final class PresenceUnlockTests: XCTestCase {
    typealias T = PresenceUnlock.UnlockTier
    private let pol = PresenceUnlock.Policy(freshnessWindowRounds: 5)

    func testBelowMaxPresenceIrrelevant() {
        var s = PresenceUnlock.State()
        PresenceUnlock.onUnlock(&s, tier: .standard)
        XCTAssertEqual(PresenceUnlock.effectiveTier(s, pol, nowRound: 1000), .standard)
        XCTAssertTrue(PresenceUnlock.allows(s, pol, nowRound: 1000, required: .standard))
        XCTAssertFalse(PresenceUnlock.allows(s, pol, nowRound: 1000, required: .max))
    }

    func testMaxRequiresFreshPresenceAndDecays() {
        var s = PresenceUnlock.State()
        PresenceUnlock.onUnlock(&s, tier: .max)
        PresenceUnlock.onPresenceTick(&s, nowRound: 100)
        XCTAssertEqual(PresenceUnlock.effectiveTier(s, pol, nowRound: 103), .max)
        XCTAssertEqual(PresenceUnlock.effectiveTier(s, pol, nowRound: 106), .standard)   // 106-100 > 5
        XCTAssertFalse(PresenceUnlock.allows(s, pol, nowRound: 106, required: .max))
        XCTAssertTrue(PresenceUnlock.allows(s, pol, nowRound: 106, required: .standard))
    }

    func testPresenceTickRestoresMaxAndNeverRegresses() {
        var s = PresenceUnlock.State()
        PresenceUnlock.onUnlock(&s, tier: .max)
        PresenceUnlock.onPresenceTick(&s, nowRound: 100)
        XCTAssertEqual(PresenceUnlock.effectiveTier(s, pol, nowRound: 110), .standard)
        PresenceUnlock.onPresenceTick(&s, nowRound: 110)
        XCTAssertEqual(PresenceUnlock.effectiveTier(s, pol, nowRound: 112), .max)
        PresenceUnlock.onPresenceTick(&s, nowRound: 90)                                  // stale/replay
        XCTAssertEqual(s.lastPresenceRound, 110)
    }

    func testDuressCapsAndDeniesNormalActions() {
        var s = PresenceUnlock.State()
        PresenceUnlock.onUnlock(&s, tier: .max, duress: true)
        PresenceUnlock.onPresenceTick(&s, nowRound: 100)
        XCTAssertEqual(PresenceUnlock.effectiveTier(s, pol, nowRound: 100), .duress)
        XCTAssertTrue(PresenceUnlock.allows(s, pol, nowRound: 100, required: .duress))
        XCTAssertFalse(PresenceUnlock.allows(s, pol, nowRound: 100, required: .basic))
    }

    func testLockResets() {
        var s = PresenceUnlock.State()
        PresenceUnlock.onUnlock(&s, tier: .max)
        PresenceUnlock.onPresenceTick(&s, nowRound: 100)
        PresenceUnlock.onLock(&s)
        XCTAssertEqual(PresenceUnlock.effectiveTier(s, pol, nowRound: 101), .locked)
    }
}
