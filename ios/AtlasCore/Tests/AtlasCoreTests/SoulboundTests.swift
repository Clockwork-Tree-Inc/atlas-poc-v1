import XCTest
@testable import AtlasCore

/// Soul-bound tokens — non-transferable, identity-bound, non-monetary participation.
/// Mirrors `backend/tests/test_soulbound.py`.
final class SoulboundTests: XCTestCase {

    private func kp(_ n: UInt8) -> HybridSign.Keypair {
        try! HybridSign.keypair(fromSeed: Data(repeating: n, count: 32))
    }
    private lazy var a = kp(1)
    private lazy var b = kp(2)
    private lazy var org = kp(9)

    func testCollectParticipationAndBalance() throws {
        let col = Participation.SoulboundCollection(holder: a.publicKey)
        for e in 1...3 {
            let t = try Participation.collectParticipation(a, epoch: e, poleCommitment: Data([UInt8(e)]))
            XCTAssertTrue(col.add(t))
        }
        XCTAssertEqual(col.balance(kind: Participation.participationKind), 3)
        XCTAssertEqual(col.epochs(), [1, 2, 3])
    }

    func testOnePerEpochNoInflation() throws {
        let col = Participation.SoulboundCollection(holder: a.publicKey)
        col.add(try Participation.collectParticipation(a, epoch: 5, poleCommitment: Data("x".utf8)))
        col.add(try Participation.collectParticipation(a, epoch: 5, poleCommitment: Data("y".utf8)))
        XCTAssertEqual(col.balance(kind: Participation.participationKind), 1)
    }

    func testCannotCollectTokenBoundToSomeoneElse() throws {
        let aToken = try Participation.collectParticipation(a, epoch: 1)
        let bCol = Participation.SoulboundCollection(holder: b.publicKey)
        XCTAssertFalse(bCol.add(aToken))
        XCTAssertEqual(bCol.balance(), 0)
    }

    func testNoTransferByRebinding() throws {
        var aToken = try Participation.collectParticipation(a, epoch: 1)
        aToken.holder = b.publicKey                       // attempt to re-home it
        XCTAssertFalse(Participation.verifySBT(aToken))   // signature no longer valid
        XCTAssertFalse(Participation.SoulboundCollection(holder: b.publicKey).add(aToken))
    }

    func testTamperedTokenRejected() throws {
        var t = try Participation.collectParticipation(a, epoch: 1)
        t.epoch = 999
        XCTAssertFalse(Participation.verifySBT(t))
    }

    func testOrgIssuedBadgeCollectibleByHolder() throws {
        let badge = try Participation.issueSBT(org, holder: a.publicKey,
                                               kind: Data("atlas/badge/pilot-2026".utf8), epoch: 1)
        XCTAssertTrue(Participation.verifySBT(badge))
        let col = Participation.SoulboundCollection(holder: a.publicKey)
        XCTAssertTrue(col.add(badge))
        XCTAssertEqual(col.balance(kind: Data("atlas/badge/pilot-2026".utf8)), 1)
        XCTAssertEqual(col.balance(kind: Participation.participationKind), 0)
    }

    func testOrgBadgeBoundToANotCollectibleByB() throws {
        let badge = try Participation.issueSBT(org, holder: a.publicKey,
                                               kind: Data("atlas/badge/pilot-2026".utf8), epoch: 1)
        XCTAssertFalse(Participation.SoulboundCollection(holder: b.publicKey).add(badge))
    }
}
