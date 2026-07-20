import XCTest
@testable import AtlasCore

/// Native-logic parity for recovery-tier selection (TRUST_LAYER.md #6) — kept in lockstep with
/// backend/tests/test_tiers.py. Asserts the ladder picks the strongest reachable tier and the
/// load-bearing guarantee: with (name+password) + a recovery person you are never locked out.
final class RecoveryTiersTests: XCTestCase {
    typealias Tier = RecoveryTiers.RecoveryTier
    typealias Factors = RecoveryTiers.AvailableFactors

    func testDevicePresentStrongestWhenYouHoldAHalf() throws {
        let f = Factors(userHalf: true, guardianQuorum: true, namePassword: true, recoveryPerson: true)
        XCTAssertEqual(try RecoveryTiers.selectTier(f), .devicePresent)
        XCTAssertEqual(RecoveryTiers.reachableTiers(f), [.devicePresent, .social, .physicalSelf])
    }

    func testSocialWhenDeviceLostButGuardiansReachable() throws {
        let f = Factors(guardianQuorum: true, namePassword: true)
        XCTAssertEqual(try RecoveryTiers.selectTier(f), .social)
    }

    func testSocialNeedsCeremonyHalfToo() {
        let f = Factors(guardianQuorum: true, namePassword: false)
        XCTAssertFalse(RecoveryTiers.reachableTiers(f).contains(.social))
    }

    func testPhysicalSelfIsTheFloor() throws {
        let f = Factors(namePassword: true, recoveryPerson: true)
        XCTAssertEqual(try RecoveryTiers.selectTier(f), .physicalSelf)
        XCTAssertTrue(RecoveryTiers.neverLockedOut(f))
    }

    func testLockedOutWithoutPasswordOrPerson() {
        XCTAssertFalse(RecoveryTiers.neverLockedOut(Factors(namePassword: true, recoveryPerson: false)))
        XCTAssertFalse(RecoveryTiers.neverLockedOut(Factors(namePassword: false, recoveryPerson: true)))
        XCTAssertThrowsError(try RecoveryTiers.selectTier(Factors(namePassword: false, recoveryPerson: true))) {
            XCTAssertEqual($0 as? RecoveryTiers.RecoveryTierError, .noTierReachable)
        }
    }

    func testDevicePresentIgnoresMissingCeremonyHalf() throws {
        let f = Factors(userHalf: true)
        XCTAssertEqual(try RecoveryTiers.selectTier(f), .devicePresent)
        XCTAssertFalse(RecoveryTiers.neverLockedOut(f))  // self-sufficient, but not the *floor*
    }

    func testTierOwnerMapComplete() {
        XCTAssertEqual(Set(RecoveryTiers.tierOwner.keys), Set(Tier.allCases))
        XCTAssertEqual(RecoveryTiers.tierOwner[.physicalSelf], "realid.recovery_anchor")
        XCTAssertEqual(RecoveryTiers.tierOwner[.social], "recovery.guardianship")
        XCTAssertEqual(RecoveryTiers.tierOwner[.devicePresent], "recovery.threshold_seal")
    }

    func testTiersOrderedByAssurance() {
        XCTAssertTrue(Tier.devicePresent > Tier.social && Tier.social > Tier.physicalSelf)
    }
}
