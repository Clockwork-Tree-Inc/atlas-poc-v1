import XCTest
@testable import AtlasCore

/// Native-logic parity for per-space pseudonyms (TRUST_LAYER.md #13) — kept in lockstep with
/// backend/tests/test_space_pseudonym.py.
final class SpacePseudonymTests: XCTestCase {
    private let root = Data("system-id-root-secret-32-bytes..".utf8)
    private let s1 = Data("family".utf8)
    private let s2 = Data("workplace".utf8)

    func testStableWithinSpaceUnlinkableAcross() {
        XCTAssertEqual(SpacePseudonym.joinSpace(root: root, spaceID: s1),
                       SpacePseudonym.joinSpace(root: root, spaceID: s1))
        let a = SpacePseudonym.joinSpace(root: root, spaceID: s1)
        let b = SpacePseudonym.joinSpace(root: root, spaceID: s2)
        XCTAssertNotEqual(a.nym, b.nym)
        XCTAssertNotEqual(a.nullifier, b.nullifier)
    }

    func testNymAndNullifierDomainSeparated() {
        XCTAssertNotEqual(SpacePseudonym.spaceNym(root: root, spaceID: s1),
                          SpacePseudonym.spaceNullifier(root: root, spaceID: s1))
    }

    func testDifferentRootsDifferentIdentities() {
        let other = Primitives.randomBytes(32)
        XCTAssertNotEqual(SpacePseudonym.spaceNym(root: root, spaceID: s1),
                          SpacePseudonym.spaceNym(root: other, spaceID: s1))
    }

    private func authority(_ roots: Data...) -> SpacePseudonym.PersonhoodAuthority {
        let a = SpacePseudonym.PersonhoodAuthority()
        for r in roots { a.enroll(root: r) }
        return a
    }

    func testRegistryOneIdentityPerVerifiedHumanIdempotent() throws {
        let auth = authority(root)
        let reg = SpacePseudonym.SpaceRegistry(spaceID: s1, authorityRoot: auth.rootDigest)
        let proof = try auth.membershipProof(root: root)
        try reg.register(root: root, membershipProof: proof)
        try reg.register(root: root, membershipProof: proof)   // idempotent
        XCTAssertEqual(reg.size, 1)
        XCTAssertTrue(reg.isMember(SpacePseudonym.spaceNym(root: root, spaceID: s1)))
    }

    func testUnverifiedRootsAreRejected() throws {
        // THE sybil fix: unenrolled roots admit zero identities.
        let auth = authority(root)                            // only `root` is verified
        let reg = SpacePseudonym.SpaceRegistry(spaceID: s1, authorityRoot: auth.rootDigest)
        let fake = Primitives.randomBytes(32)
        let bogusProof: [Merkle.ProofStep] = [(Primitives.randomBytes(32), true)]
        XCTAssertThrowsError(try reg.register(root: fake, membershipProof: bogusProof)) {
            XCTAssertEqual($0 as? SpacePseudonym.SpaceError, .personhood)
        }
        XCTAssertEqual(reg.size, 0)
    }

    func testCountsDistinctVerifiedHumans() throws {
        let roots = (0..<4).map { _ in Primitives.randomBytes(32) }
        let auth = SpacePseudonym.PersonhoodAuthority()
        roots.forEach { auth.enroll(root: $0) }
        let reg = SpacePseudonym.SpaceRegistry(spaceID: s1, authorityRoot: auth.rootDigest)
        for r in roots { try reg.register(root: r, membershipProof: try auth.membershipProof(root: r)) }
        XCTAssertEqual(reg.size, 4)
    }

    func testPersonhoodVerifyAndWrongAuthorityFails() throws {
        let auth = authority(root, Primitives.randomBytes(32))
        let proof = try auth.membershipProof(root: root)
        XCTAssertTrue(SpacePseudonym.verifyPersonhood(root: root, proof: proof, authorityRoot: auth.rootDigest))
        XCTAssertFalse(SpacePseudonym.verifyPersonhood(root: root, proof: proof, authorityRoot: Primitives.randomBytes(32)))
    }
}
