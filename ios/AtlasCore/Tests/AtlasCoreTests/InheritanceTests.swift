import XCTest
@testable import AtlasCore

final class InheritanceTests: XCTestCase {
    private func kp(_ n: UInt8) -> HybridSign.Keypair { try! HybridSign.keypair(fromSeed: Data(repeating: n, count: 32)) }
    private let gate = Data("gate-id-0123456789ab".utf8)   // >= 16 bytes

    private func policy(window: Int = 10) throws -> (Inheritance.InheritancePolicy, HybridSign.Keypair, HybridSign.Keypair) {
        let owner = kp(1), executor = kp(2)
        let p = try Inheritance.InheritancePolicy(gateID: gate, ownerPub: owner.publicKey,
                                                  triggerPub: executor.publicKey, vetoWindowRounds: window)
        return (p, owner, executor)
    }
    private func triggerSig(_ ex: HybridSign.Keypair, _ round: Int) -> Data {
        try! HybridSign.sign(ex, Inheritance.triggerMessage(gateID: gate, atRound: round))
    }
    private func vetoSig(_ owner: HybridSign.Keypair, _ round: Int, _ beacon: Data) -> Data {
        try! HybridSign.sign(owner, Inheritance.vetoMessage(gateID: gate, atRound: round, beaconSig: beacon))
    }

    func testHappyPathTriggerThenElapseThenRelease() throws {
        let (p, _, ex) = try policy()
        let s = Inheritance.GateState()
        XCTAssertEqual(Inheritance.status(p, s, nowRound: 100), "armed")
        try Inheritance.applyTrigger(p, s, atRound: 100, signature: triggerSig(ex, 100))
        XCTAssertEqual(Inheritance.status(p, s, nowRound: 105), "challenge")
        XCTAssertFalse(Inheritance.canRelease(p, s, nowRound: 105))
        XCTAssertEqual(Inheritance.status(p, s, nowRound: 111), "releasable")
        XCTAssertTrue(Inheritance.canRelease(p, s, nowRound: 111))
        try Inheritance.markReleased(p, s, nowRound: 111)
        XCTAssertEqual(Inheritance.status(p, s, nowRound: 111), "released")
    }

    func testVetoAbortsTheTrigger() throws {
        let (p, owner, ex) = try policy()
        let s = Inheritance.GateState()
        try Inheritance.applyTrigger(p, s, atRound: 100, signature: triggerSig(ex, 100))
        // owner proves liveness at round 105, bound to a post-trigger beacon signature
        try Inheritance.applyVeto(p, s, atRound: 105, beaconSig: Data("beacon-105".utf8),
                                  signature: vetoSig(owner, 105, Data("beacon-105".utf8)))
        XCTAssertEqual(s.vetoCount, 1)
        XCTAssertEqual(Inheritance.status(p, s, nowRound: 200), "armed")   // aborted -> can't release
        XCTAssertFalse(Inheritance.canRelease(p, s, nowRound: 200))
    }

    func testVetoOutsideWindowRejected() throws {
        let (p, owner, ex) = try policy()
        let s = Inheritance.GateState()
        try Inheritance.applyTrigger(p, s, atRound: 100, signature: triggerSig(ex, 100))
        XCTAssertThrowsError(try Inheritance.applyVeto(p, s, atRound: 200, beaconSig: Data("b".utf8),
                                                       signature: vetoSig(owner, 200, Data("b".utf8)))) { e in
            XCTAssertEqual(e as? Inheritance.InheritanceError, .windowElapsed)
        }
    }

    func testVetoWithNoTriggerRejected() throws {
        let (p, owner, _) = try policy()
        let s = Inheritance.GateState()
        XCTAssertThrowsError(try Inheritance.applyVeto(p, s, atRound: 5, beaconSig: Data("b".utf8),
                                                       signature: vetoSig(owner, 5, Data("b".utf8)))) { e in
            XCTAssertEqual(e as? Inheritance.InheritanceError, .notTriggered)
        }
    }

    func testBadTriggerAuthorityRejected() throws {
        let (p, _, _) = try policy()
        let s = Inheritance.GateState()
        let imposter = kp(9)
        XCTAssertThrowsError(try Inheritance.applyTrigger(p, s, atRound: 100, signature: triggerSig(imposter, 100))) { e in
            XCTAssertEqual(e as? Inheritance.InheritanceError, .badAuthority)
        }
    }

    func testCannotReleaseBeforeWindowElapses() throws {
        let (p, _, ex) = try policy()
        let s = Inheritance.GateState()
        try Inheritance.applyTrigger(p, s, atRound: 100, signature: triggerSig(ex, 100))
        XCTAssertThrowsError(try Inheritance.markReleased(p, s, nowRound: 105)) { e in
            XCTAssertEqual(e as? Inheritance.InheritanceError, .releaseNotMet)
        }
    }

    func testRetriggerAfterVetoCanEventuallyRelease() throws {
        let (p, owner, ex) = try policy()
        let s = Inheritance.GateState()
        try Inheritance.applyTrigger(p, s, atRound: 100, signature: triggerSig(ex, 100))
        try Inheritance.applyVeto(p, s, atRound: 105, beaconSig: Data("b".utf8), signature: vetoSig(owner, 105, Data("b".utf8)))
        // later, the owner really is gone: a fresh trigger with no veto releases
        try Inheritance.applyTrigger(p, s, atRound: 500, signature: triggerSig(ex, 500))
        XCTAssertTrue(Inheritance.canRelease(p, s, nowRound: 511))
        try Inheritance.markReleased(p, s, nowRound: 511)
        XCTAssertTrue(s.released)
    }

    func testBadPolicyRejected() {
        XCTAssertThrowsError(try Inheritance.InheritancePolicy(gateID: Data("short".utf8),
                                                               ownerPub: kp(1).publicKey,
                                                               triggerPub: kp(2).publicKey, vetoWindowRounds: 10))
        XCTAssertThrowsError(try Inheritance.InheritancePolicy(gateID: gate, ownerPub: kp(1).publicKey,
                                                               triggerPub: kp(2).publicKey, vetoWindowRounds: 0))
    }
}
