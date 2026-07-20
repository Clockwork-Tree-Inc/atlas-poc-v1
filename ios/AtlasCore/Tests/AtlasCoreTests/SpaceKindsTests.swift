import XCTest
@testable import AtlasCore

/// Space kinds + authority-based invitation (Phase B) — mirrors backend/tests/test_space_kinds.py.
final class SpaceKindsTests: XCTestCase {
    let SID = Data("space-42".utf8)

    func owner() throws -> (FSSign.FSPublicKey, FSSign.FSSigner) {
        try FSSign.keygen(seed: Data((0..<32).map(UInt8.init)), height: 3)
    }
    func kp(_ n: UInt8) -> HybridSign.Keypair { try! HybridSign.keypair(fromSeed: Data(repeating: n, count: 32)) }

    func testConstructorsAndDefaultPersistence() throws {
        let (pub, _) = try owner()
        XCTAssertEqual(Spaces.commons(SID, pub).kind, .commons)
        XCTAssertEqual(Spaces.commons(SID, pub).persistence, .publicMode)      // default per kind
        XCTAssertEqual(Spaces.direct(SID, pub).persistence, .privateMode)
        XCTAssertEqual(Spaces.commons(SID, pub, .present).persistence, .present)  // any space, any mode
        XCTAssertTrue(Spaces.persistenceBackend(.publicMode).contains("GlobalAnchor"))
    }

    func testInviteMemberRoleAndGate() throws {
        let (pub, signer) = try owner()
        let a = kp(2)
        let space = Spaces.makeSpace(SID, kind: .friends, ownerRoot: pub)
        let g = try Spaces.invite(space, ownerSigner: signer, invitee: a.publicKey, role: .member)
        XCTAssertEqual(try Spaces.memberRole(space, [g], now: 1000), .member)
        XCTAssertTrue(Spaces.hasRole(space, [g], atLeast: .member, now: 1000))
        XCTAssertFalse(Spaces.hasRole(space, [g], atLeast: .admin, now: 1000))   // gate fail-closed
    }

    func testDelegationAttenuatesAndCrossSpaceRejected() throws {
        let (pub, signer) = try owner()
        let a = kp(2), b = kp(3)
        let space = Spaces.makeSpace(SID, kind: .host, ownerRoot: pub)
        let admin = try Spaces.invite(space, ownerSigner: signer, invitee: a.publicKey, role: .admin, delegable: true)
        let guest = try Spaces.subInvite(admin, holder: a, invitee: b.publicKey, role: .guest)
        XCTAssertEqual(try Spaces.memberRole(space, [admin, guest], now: 1000), .guest)
        XCTAssertThrowsError(try Spaces.subInvite(admin, holder: a, invitee: b.publicKey, role: .owner))  // can't exceed
        let other = Spaces.commons(Data("space-B".utf8), pub)
        XCTAssertThrowsError(try Spaces.memberRole(other, [admin], now: 1000))   // cross-space rejected
    }
}
