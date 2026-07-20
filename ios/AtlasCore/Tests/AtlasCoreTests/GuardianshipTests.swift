import XCTest
@testable import AtlasCore

/// Native-logic parity for guardianship (TRUST_LAYER.md #4/#5) — kept in lockstep with
/// backend/tests/test_guardianship.py. The crypto is ThresholdSeal (already parity-covered);
/// these assert the policy logic: the anti-collusion invariant + the witting veto/approval gate.
final class GuardianshipTests: XCTestCase {

    private let secret = Data("recovery-secret-under-guardianship".utf8)
    private let userHalf = Data("user-tsk-half".utf8)

    private func g(_ label: String, _ kind: Guardianship.GuardianKind = .silent,
                   institutional: Bool = false) -> Guardianship.Guardian {
        Guardianship.Guardian(custodian: ThresholdSeal.Custodian(label: label, institutional: institutional),
                              kind: kind)
    }
    // 2 personal silent + 1 witting human + 2 institutional operators; institutional(2) < m(3)
    private func mixedSet() -> [Guardianship.Guardian] {
        [g("home-node"), g("laptop"), g("spouse", .witting),
         g("op-eu", institutional: true), g("op-us", institutional: true)]
    }

    func testRoundTrip() throws {
        let policy = try Guardianship.GuardianshipPolicy(guardians: mixedSet(), m: 3)
        let (sealed, shares) = try Guardianship.seal(secret, userHalf: userHalf, policy: policy,
                                                     storage: .guardians, context: Data("ctx".utf8))
        let got = try Guardianship.reconstruct(sealed, userHalf: userHalf,
            presentedShares: [shares[0], shares[1], shares[3]], policy: policy)  // home, laptop, op-eu
        XCTAssertEqual(got, secret)
    }

    func testPolicyRejectsInstitutionalReachingThreshold() {
        let guardians = [g("op-eu", institutional: true), g("op-us", institutional: true),
                         g("op-asia", institutional: true), g("home-node")]
        XCTAssertThrowsError(try Guardianship.GuardianshipPolicy(guardians: guardians, m: 3)) {
            guard case Guardianship.GuardianshipError.institutionalThreshold = $0 else {
                return XCTFail("expected institutionalThreshold, got \($0)")
            }
        }
    }

    func testPolicyAcceptsInstitutionalBelowThreshold() throws {
        _ = try Guardianship.GuardianshipPolicy(guardians: mixedSet(), m: 3)  // must not throw
    }

    func testReconstructionRejectsAllInstitutionalPresentedSet() throws {
        let guardians = [g("op-eu", institutional: true), g("op-us", institutional: true),
                         g("op-asia", institutional: true), g("home-node"), g("laptop")]
        let policy = try Guardianship.GuardianshipPolicy(guardians: guardians, m: 4)
        let (sealed, shares) = try Guardianship.seal(secret, userHalf: userHalf, policy: policy,
                                                     storage: .serverSharded)
        XCTAssertThrowsError(try Guardianship.reconstruct(sealed, userHalf: userHalf,
            presentedShares: [shares[0], shares[1], shares[2]], policy: policy)) {
            guard case Guardianship.GuardianshipError.institutionalThreshold = $0 else {
                return XCTFail("expected institutionalThreshold, got \($0)")
            }
        }
    }

    func testWittingVetoAborts() throws {
        let policy = try Guardianship.GuardianshipPolicy(guardians: mixedSet(), m: 3)
        let (sealed, shares) = try Guardianship.seal(secret, userHalf: userHalf, policy: policy,
                                                     storage: .guardians)
        XCTAssertThrowsError(try Guardianship.reconstruct(sealed, userHalf: userHalf,
            presentedShares: [shares[0], shares[1], shares[3]], policy: policy,
            wittingVetoes: ["spouse"])) {
            guard case Guardianship.GuardianshipError.wittingVeto = $0 else {
                return XCTFail("expected wittingVeto, got \($0)")
            }
        }
    }

    func testMinWittingApprovalsEnforced() throws {
        let policy = try Guardianship.GuardianshipPolicy(guardians: mixedSet(), m: 3, minWittingApprovals: 1)
        let (sealed, shares) = try Guardianship.seal(secret, userHalf: userHalf, policy: policy,
                                                     storage: .guardians)
        let subset = [shares[0], shares[1], shares[3]]
        XCTAssertThrowsError(try Guardianship.reconstruct(sealed, userHalf: userHalf,
            presentedShares: subset, policy: policy))  // no approvals
        XCTAssertEqual(try Guardianship.reconstruct(sealed, userHalf: userHalf,
            presentedShares: subset, policy: policy, wittingApprovals: ["spouse"]), secret)
    }

    func testForgedApprovalFromUnknownLabelIgnored() throws {
        let policy = try Guardianship.GuardianshipPolicy(guardians: mixedSet(), m: 3, minWittingApprovals: 1)
        let (sealed, shares) = try Guardianship.seal(secret, userHalf: userHalf, policy: policy,
                                                     storage: .guardians)
        XCTAssertThrowsError(try Guardianship.reconstruct(sealed, userHalf: userHalf,
            presentedShares: [shares[0], shares[1], shares[3]], policy: policy,
            wittingApprovals: ["attacker"]))  // not a witting guardian
    }

    func testVetoFromNonWittingIgnored() throws {
        let policy = try Guardianship.GuardianshipPolicy(guardians: mixedSet(), m: 3)
        let (sealed, shares) = try Guardianship.seal(secret, userHalf: userHalf, policy: policy,
                                                     storage: .guardians)
        // neither "home-node" nor "outsider" is a witting guardian -> no veto
        XCTAssertEqual(try Guardianship.reconstruct(sealed, userHalf: userHalf,
            presentedShares: [shares[0], shares[1], shares[3]], policy: policy,
            wittingVetoes: ["home-node", "outsider"]), secret)
    }

    func testBelowThresholdFails() throws {
        let policy = try Guardianship.GuardianshipPolicy(guardians: mixedSet(), m: 3)
        let (sealed, shares) = try Guardianship.seal(secret, userHalf: userHalf, policy: policy,
                                                     storage: .guardians)
        XCTAssertThrowsError(try Guardianship.reconstruct(sealed, userHalf: userHalf,
            presentedShares: [shares[0], shares[3]], policy: policy)) {  // only 2
            guard case ThresholdSeal.SealError.thresholdNotMet = $0 else {
                return XCTFail("expected thresholdNotMet, got \($0)")
            }
        }
    }

    func testWrongUserHalfFails() throws {
        let policy = try Guardianship.GuardianshipPolicy(guardians: mixedSet(), m: 3)
        let (sealed, shares) = try Guardianship.seal(secret, userHalf: userHalf, policy: policy,
                                                     storage: .guardians)
        XCTAssertThrowsError(try Guardianship.reconstruct(sealed, userHalf: Data("wrong".utf8),
            presentedShares: [shares[0], shares[1], shares[3]], policy: policy)) {
            guard case ThresholdSeal.SealError.unsealFailed = $0 else {
                return XCTFail("expected unsealFailed, got \($0)")
            }
        }
    }

    func testMinApprovalsCannotExceedWittingCount() {
        XCTAssertThrowsError(try Guardianship.GuardianshipPolicy(
            guardians: mixedSet(), m: 3, minWittingApprovals: 2)) {  // only 1 witting
            guard case Guardianship.GuardianshipError.policyInvalid = $0 else {
                return XCTFail("expected policyInvalid, got \($0)")
            }
        }
    }
}
