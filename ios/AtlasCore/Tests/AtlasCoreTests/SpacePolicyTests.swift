import XCTest
@testable import AtlasCore

final class SpacePolicyTests: XCTestCase {
    typealias SG = SpaceGovernance
    private func kp(_ n: UInt8) -> HybridSign.Keypair { try! HybridSign.keypair(fromSeed: Data(repeating: n, count: 32)) }
    private func sign(_ k: HybridSign.Keypair, _ c: SG.Change) -> Data { try! HybridSign.sign(k, c.body()) }

    func testGenesisCreatorIsSoleGovernor() {
        let creator = kp(1)
        let p = SG.SpacePolicy.genesis(spaceID: Data("space:acme".utf8), creator: creator.publicKey)
        XCTAssertEqual(p.roleOf(creator.publicKey), .governor)
        XCTAssertEqual(p.quorum, 1)
        XCTAssertTrue(p.verifyLog())
        XCTAssertFalse(p.head().isEmpty)
    }

    func testGovernorGrantsReaderAndCapabilities() throws {
        let gov = kp(1), alice = kp(2)
        let p = SG.SpacePolicy.genesis(spaceID: Data("s".utf8), creator: gov.publicKey)
        let ch = try p.propose("grant", target: alice.publicKey, role: .reader, epoch: 1)
        try p.authorize(ch, approvals: [(gov.publicKey, sign(gov, ch))])
        XCTAssertTrue(p.can(alice.publicKey, .reader))
        XCTAssertFalse(p.can(alice.publicKey, .contributor))
        XCTAssertTrue(p.can(gov.publicKey, .governor))
        XCTAssertTrue(p.verifyLog())
    }

    func testChangeWithoutQuorumRejected() throws {
        let gov = kp(1), outsider = kp(9), target = kp(2)
        let p = SG.SpacePolicy.genesis(spaceID: Data("s".utf8), creator: gov.publicKey)
        let ch = try p.propose("grant", target: target.publicKey, role: .reader, epoch: 1)
        XCTAssertThrowsError(try p.authorize(ch, approvals: [(outsider.publicKey, sign(outsider, ch))]))
        XCTAssertNil(p.roleOf(target.publicKey))
    }

    func testTwoOfTwoGovernance() throws {
        let g1 = kp(1), g2 = kp(2), target = kp(3)
        let p = SG.SpacePolicy.genesis(spaceID: Data("s".utf8), creator: g1.publicKey)
        let addG2 = try p.propose("grant", target: g2.publicKey, role: .governor, epoch: 1)
        try p.authorize(addG2, approvals: [(g1.publicKey, sign(g1, addG2))])
        let setq = try p.propose("set_quorum", quorum: 2, epoch: 2)
        try p.authorize(setq, approvals: [(g1.publicKey, sign(g1, setq))])
        XCTAssertEqual(p.quorum, 2)

        let ch = try p.propose("grant", target: target.publicKey, role: .contributor, epoch: 3)
        XCTAssertThrowsError(try p.authorize(ch, approvals: [(g1.publicKey, sign(g1, ch))]))
        let ch2 = try p.propose("grant", target: target.publicKey, role: .contributor, epoch: 3)
        try p.authorize(ch2, approvals: [(g1.publicKey, sign(g1, ch2)), (g2.publicKey, sign(g2, ch2))])
        XCTAssertTrue(p.can(target.publicKey, .contributor))
    }

    func testRevokeForwardOnlyAndLogged() throws {
        let gov = kp(1), alice = kp(2)
        let p = SG.SpacePolicy.genesis(spaceID: Data("s".utf8), creator: gov.publicKey)
        let grant = try p.propose("grant", target: alice.publicKey, role: .reader, epoch: 1)
        try p.authorize(grant, approvals: [(gov.publicKey, sign(gov, grant))])
        let rev = try p.propose("revoke", target: alice.publicKey, epoch: 2)
        try p.authorize(rev, approvals: [(gov.publicKey, sign(gov, rev))])
        XCTAssertNil(p.roleOf(alice.publicKey))
        XCTAssertEqual(p.log.count, 3)
        XCTAssertTrue(p.verifyLog())
    }

    func testStaleChangeRejected() throws {
        let g1 = kp(1), a = kp(2), b = kp(3)
        let p = SG.SpacePolicy.genesis(spaceID: Data("s".utf8), creator: g1.publicKey)
        let first = try p.propose("grant", target: a.publicKey, role: .reader, epoch: 1)
        let stale = try p.propose("grant", target: b.publicKey, role: .reader, epoch: 1)
        try p.authorize(first, approvals: [(g1.publicKey, sign(g1, first))])
        XCTAssertThrowsError(try p.authorize(stale, approvals: [(g1.publicKey, sign(g1, stale))])) { err in
            XCTAssertEqual(err as? SG.PolicyError, .stale)
        }
    }

    func testMembersAtRoleIsEligibleSetBasis() throws {
        let g1 = kp(1), g2 = kp(2), worker = kp(3)
        let p = SG.SpacePolicy.genesis(spaceID: Data("s".utf8), creator: g1.publicKey)
        let a1 = try p.propose("grant", target: g2.publicKey, role: .governor, epoch: 1)
        try p.authorize(a1, approvals: [(g1.publicKey, sign(g1, a1))])
        let a2 = try p.propose("grant", target: worker.publicKey, role: .contributor, epoch: 2)
        try p.authorize(a2, approvals: [(g1.publicKey, sign(g1, a2))])
        XCTAssertEqual(Set(p.membersAt(.governor)), Set([g1.publicKey.encode(), g2.publicKey.encode()]))
        XCTAssertEqual(p.membersAt(.contributor).count, 3)
    }
}
