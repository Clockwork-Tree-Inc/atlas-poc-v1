import XCTest
@testable import AtlasCore

/// Native-logic parity for group spaces (TRUST_LAYER.md #12) — kept in lockstep with
/// backend/tests/test_spaces.py. The crypto (Shamir, SpacePseudonym, AEAD/HKDF) is already
/// parity-covered; these assert the space composition.
final class SpacesTests: XCTestCase {
    typealias Policy = Spaces.SpacePolicy
    private let sid = Data("family".utf8)

    private func roots(_ n: Int) -> [Data] { (0..<n).map { _ in Primitives.randomBytes(32) } }

    func testMembersJoinUnderNymsNotRoots() throws {
        let rs = roots(3)
        let (space, roster) = try Spaces.createSpace(spaceID: sid, memberRoots: rs,
            policy: Policy(accessThreshold: 2, governanceThreshold: 2))
        XCTAssertEqual(space.size, 3)
        for r in rs {
            let nym = SpacePseudonym.spaceNym(root: r, spaceID: sid)
            XCTAssertTrue(space.isMember(nym) && roster[nym] != nil)
            XCTAssertFalse(space.memberNyms.contains(r))     // the root is never in the space
        }
    }

    func testPolicyValidation() {
        XCTAssertThrowsError(try Spaces.createSpace(spaceID: sid, memberRoots: roots(3),
            policy: Policy(accessThreshold: 1, governanceThreshold: 2)))
        XCTAssertThrowsError(try Spaces.createSpace(spaceID: sid, memberRoots: roots(2),
            policy: Policy(accessThreshold: 3, governanceThreshold: 2)))
    }

    func testSealOpenThresholdAndFailClosed() throws {
        let rs = roots(3)
        let (space, roster) = try Spaces.createSpace(spaceID: sid, memberRoots: rs,
            policy: Policy(accessThreshold: 2, governanceThreshold: 2))
        let shares = Array(roster.values)
        let item = try Spaces.sealToVault(space, plaintext: Data("family photo".utf8),
                                          presentShares: Array(shares.prefix(2)))
        XCTAssertNil(item.ciphertext.range(of: Data("family photo".utf8)))   // only ciphertext
        XCTAssertEqual(try Spaces.openVault(space, item: item, presentShares: Array(shares.prefix(2))),
                       Data("family photo".utf8))
        XCTAssertThrowsError(try Spaces.openVault(space, item: item, presentShares: Array(shares.prefix(1))))
    }

    func testTenantIsolation() throws {
        let rs = roots(3)
        let (a, ra) = try Spaces.createSpace(spaceID: Data("space-A".utf8), memberRoots: rs,
            policy: Policy(accessThreshold: 2, governanceThreshold: 2))
        let (b, rb) = try Spaces.createSpace(spaceID: Data("space-B".utf8), memberRoots: rs,
            policy: Policy(accessThreshold: 2, governanceThreshold: 2))
        let item = try Spaces.sealToVault(a, plaintext: Data("A only".utf8),
                                          presentShares: Array(ra.values.prefix(2)))
        XCTAssertThrowsError(try Spaces.openVault(b, item: item, presentShares: Array(rb.values.prefix(2))))
    }

    func testAddMemberReshareVaultSurvives() throws {
        let rs = roots(3)
        let (space, roster) = try Spaces.createSpace(spaceID: sid, memberRoots: rs,
            policy: Policy(accessThreshold: 2, governanceThreshold: 2))
        let item = try Spaces.sealToVault(space, plaintext: Data("shared note".utf8),
                                          presentShares: Array(roster.values.prefix(2)))
        let newcomer = Primitives.randomBytes(32)
        let (updated, newRoster) = try Spaces.addMember(space, newMemberRoot: newcomer,
            currentMemberRoots: rs, governanceShares: Array(roster.values.prefix(2)))
        XCTAssertEqual(updated.size, 4)
        XCTAssertEqual(try Spaces.openVault(updated, item: item, presentShares: Array(newRoster.values.prefix(2))),
                       Data("shared note".utf8))
    }

    func testRemovedMemberTrulyRevoked() throws {
        let rs = roots(3)
        let (space, roster) = try Spaces.createSpace(spaceID: sid, memberRoots: rs,
            policy: Policy(accessThreshold: 2, governanceThreshold: 2))
        _ = try Spaces.sealToVault(space, plaintext: Data("members only".utf8),
                                   presentShares: Array(roster.values.prefix(2)))
        let removedOld = roster[SpacePseudonym.spaceNym(root: rs[2], spaceID: sid)]!
        let survivorOld = roster[SpacePseudonym.spaceNym(root: rs[0], spaceID: sid)]!
        let (updated, newRoster) = try Spaces.removeMember(space, targetRoot: rs[2],
            remainingMemberRoots: Array(rs.prefix(2)), governanceShares: Array(roster.values.prefix(2)))
        XCTAssertEqual(updated.size, 2)
        let rekeyed = updated.store[0]                     // re-encrypted under the new root
        let newShares = Array(newRoster.values)

        XCTAssertThrowsError(try Spaces.openVault(updated, item: rekeyed, presentShares: [removedOld, survivorOld]))
        XCTAssertThrowsError(try Spaces.openVault(updated, item: rekeyed, presentShares: [newShares[0], removedOld]))
        XCTAssertEqual(try Spaces.openVault(updated, item: rekeyed, presentShares: Array(newShares.prefix(2))),
                       Data("members only".utf8))
    }

    func testGovernanceBelowAccessRejected() {
        XCTAssertThrowsError(try Spaces.createSpace(spaceID: sid, memberRoots: roots(4),
            policy: Policy(accessThreshold: 3, governanceThreshold: 2)))
    }

    func testGovernanceThresholdEnforced() throws {
        let rs = roots(3)
        let (space, roster) = try Spaces.createSpace(spaceID: sid, memberRoots: rs,
            policy: Policy(accessThreshold: 2, governanceThreshold: 3))
        XCTAssertThrowsError(try Spaces.addMember(space, newMemberRoot: Primitives.randomBytes(32),
            currentMemberRoots: rs, governanceShares: Array(roster.values.prefix(2)))) {
            XCTAssertEqual($0 as? Spaces.SpaceError, .governance)
        }
    }
}
