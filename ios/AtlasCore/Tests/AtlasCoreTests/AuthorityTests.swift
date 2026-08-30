import XCTest
@testable import AtlasCore

/// Swift authority engine — a core subset of the Python adversarial suite
/// (backend/tests/test_authority.py), proving the mirrored engine runs and fails closed. The full
/// A1–A16 pressure-test is the Python reference; grant_id encoding parity is in ParityTests.
final class AuthorityTests: XCTestCase {
    let RES = Data("space-1".utf8)
    let READ = 1, POST = 2, ADMIN = 3, OWNER = 4

    func kp(_ n: UInt8) -> HybridSign.Keypair { try! HybridSign.keypair(fromSeed: Data(repeating: n, count: 32)) }

    private func signed(_ signer: HybridSign.Keypair, grantee: HybridSign.PublicKey,
                        rights: Authority.RightSet, depth: Int, parent: Data) throws -> Authority.Grant {
        var g = Authority.Grant(grantor: signer.publicKey, grantee: grantee, resource: RES, rights: rights,
                                caveats: [], delegableDepth: depth, parent: parent, epoch: 0)
        g.sig = try HybridSign.sign(signer, g.body())
        return g
    }

    func testHappyDelegationChain() throws {
        let root = kp(1), a = kp(2), b = kp(3)
        let g0 = try Authority.issue(root: root, grantee: a.publicKey, resource: RES, rights: .init(ADMIN), delegableDepth: 2)
        let g1 = try Authority.delegate(g0, holder: a, grantee: b.publicKey, rights: .init(POST))
        let eff = try Authority.verifyChain([g0, g1], resource: RES, resourceRoot: root.publicKey, now: 1000)
        XCTAssertEqual(eff, Authority.RightSet(POST))
    }

    func testA1EscalateRejectedAtVerify() throws {
        let root = kp(1), a = kp(2), b = kp(3)
        let g0 = try Authority.issue(root: root, grantee: a.publicKey, resource: RES, rights: .init(POST), delegableDepth: 2)
        let evil = try signed(a, grantee: b.publicKey, rights: .init(ADMIN), depth: 1, parent: g0.grantId())
        XCTAssertThrowsError(try Authority.verifyChain([g0, evil], resource: RES, resourceRoot: root.publicKey, now: 1000))
    }

    func testA13RotatedOutRootRetiredIncludingBackdating() throws {
        // A13 (open, safe interim): a rotated-out root is RETIRED — none of its grants verify, incl.
        // the backdating attack (epoch == cutoff) the old epoch-cutoff check accepted. Real fix is a
        // forward-secure ratcheted root signer (AUTHORITY_MODEL A13).
        let root = kp(1), x = kp(9), newroot = kp(20)
        var cert = Authority.RotationCert(resource: RES, oldRoot: root.publicKey, newRoot: newroot.publicKey, epoch: 100)
        cert.sig = try HybridSign.sign(root, cert.body())
        for epoch: UInt64 in [3, 100, 500] {   // pre-cut, at-cut (backdating), post-cut — all rejected
            let g = try Authority.issue(root: root, grantee: x.publicKey, resource: RES, rights: .init(OWNER), epoch: epoch)
            XCTAssertThrowsError(try Authority.verifyChain([g], resource: RES, resourceRoot: newroot.publicKey,
                                                           now: 500, rotations: [cert]))
        }
    }

    func testA14ProofOfPossession() throws {
        let root = kp(1), a = kp(2), x = kp(9)
        let g0 = try Authority.issue(root: root, grantee: a.publicKey, resource: RES, rights: .init(READ))
        let challenge = Data("fresh-nonce".utf8)
        let good = try HybridSign.sign(a, challenge)
        XCTAssertEqual(try Authority.verifyAccess([g0], challenge: challenge, proof: good, now: 1000,
                                                  resource: RES, resourceRoot: root.publicKey), Authority.RightSet(READ))
        let bad = try HybridSign.sign(x, challenge)
        XCTAssertThrowsError(try Authority.verifyAccess([g0], challenge: challenge, proof: bad, now: 1000,
                                                        resource: RES, resourceRoot: root.publicKey))
    }

    func testA15UnauthorizedRevocationIgnored() throws {
        let root = kp(1), a = kp(2), b = kp(3), x = kp(9)
        let g0 = try Authority.issue(root: root, grantee: a.publicKey, resource: RES, rights: .init(ADMIN), delegableDepth: 1)
        let g1 = try Authority.delegate(g0, holder: a, grantee: b.publicKey, rights: .init(READ))
        let evilRev = try Authority.revoke(g1, revoker: x)                      // stranger -> ignored
        XCTAssertEqual(try Authority.verifyChain([g0, g1], resource: RES, resourceRoot: root.publicKey,
                                                 now: 1000, revocations: [evilRev]), Authority.RightSet(READ))
        let goodRev = try Authority.revoke(g1, revoker: root)                   // ancestor -> honored
        XCTAssertThrowsError(try Authority.verifyChain([g0, g1], resource: RES, resourceRoot: root.publicKey,
                                                       now: 1000, revocations: [goodRev]))
    }

    func testA16UnknownCaveatFailsClosed() throws {
        let root = kp(1), a = kp(2)
        let g0 = try Authority.issue(root: root, grantee: a.publicKey, resource: RES, rights: .init(READ),
                                     caveats: [Authority.Caveat("geo-fence", "EU")])
        XCTAssertThrowsError(try Authority.verifyChain([g0], resource: RES, resourceRoot: root.publicKey, now: 1000))
        XCTAssertEqual(try Authority.verifyChain([g0], resource: RES, resourceRoot: root.publicKey, now: 1000,
                                                 understoodCaveats: ["geo-fence"]), Authority.RightSet(READ))
    }

    // A13 fix: forward-secure ratcheted root — happy path, delegation, and the backdating kill.
    func testFSRootHappyDelegationAndBackdatingKilled() throws {
        let (pub, signer) = try FSSign.keygen(seed: Data((0..<32).map(UInt8.init)), height: 3)
        let a = kp(2), b = kp(3), x = kp(9)
        let g0 = try Authority.issueFS(signer, grantee: a.publicKey, resource: RES, rights: .init(ADMIN), delegableDepth: 1)
        XCTAssertEqual(try Authority.verifyChain([g0], resource: RES, fsRoot: pub, now: 1000), Authority.RightSet(ADMIN))
        let g1 = try Authority.delegate(g0, holder: a, grantee: b.publicKey, rights: .init(READ))
        XCTAssertEqual(try Authority.verifyChain([g0, g1], resource: RES, fsRoot: pub, now: 1000), Authority.RightSet(READ))
        // compromise: advance to epoch 3, then forge an "epoch 0" root grant signed by the current leaf
        for _ in 0..<3 { try signer.advance() }
        let leaf3 = try HybridSign.keypair(fromSeed: FSSign.leafSeed(signer.state))
        var forged = Authority.Grant(grantor: leaf3.publicKey, grantee: x.publicKey, resource: RES,
                                     rights: .init(OWNER), caveats: [], delegableDepth: 0,
                                     parent: Authority.ROOT, epoch: 0)
        forged.sig = try HybridSign.sign(leaf3, forged.body())
        forged.fsEpoch = 0
        forged.fsAuthPath = FSSign.authPath(signer.levels, 0)
        XCTAssertThrowsError(try Authority.verifyChain([forged], resource: RES, fsRoot: pub, now: 1000))
    }
}
