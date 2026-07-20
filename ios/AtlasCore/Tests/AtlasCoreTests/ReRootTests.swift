import XCTest
@testable import AtlasCore

/// Ledger-anchored re-root — compromise recovery (mirrors backend/tests/test_reroot.py).
final class ReRootTests: XCTestCase {
    let RES = Data("space-1".utf8)
    func kp(_ n: UInt8) -> HybridSign.Keypair { try! HybridSign.keypair(fromSeed: Data(repeating: n, count: 32)) }
    func root(_ s: UInt8) throws -> (FSSign.FSPublicKey, FSSign.FSSigner) {
        try FSSign.keygen(seed: Data(repeating: s, count: 32), height: 3)
    }

    func testNoRerootIsGenesis() throws {
        let (g, _) = try root(1)
        XCTAssertEqual(Authority.currentRoot(RES, recoveryPublic: kp(1).publicKey, genesisRoot: g, reroots: []), g)
    }

    func testValidRerootMovesRoot() throws {
        let (g, _) = try root(1); let (n, _) = try root(2); let recovery = kp(1)
        let rr = try Authority.makeReroot(recovery, resource: RES, newRoot: n, effectiveEpoch: 5)
        XCTAssertEqual(Authority.currentRoot(RES, recoveryPublic: recovery.publicKey, genesisRoot: g, reroots: [rr]), n)
    }

    func testThiefCannotReroot() throws {
        let (g, _) = try root(1); let (evil, _) = try root(3); let recovery = kp(1), thief = kp(9)
        var forged = Authority.ReRoot(resource: RES, newRoot: evil, effectiveEpoch: 9)
        forged.sig = try HybridSign.sign(thief, forged.body())   // signed by thief, not recovery
        XCTAssertEqual(Authority.currentRoot(RES, recoveryPublic: recovery.publicKey, genesisRoot: g, reroots: [forged]), g)
    }

    func testCompromiseRecoveryEndToEnd() throws {
        let (g, gs) = try root(1); let (n, ns) = try root(2); let recovery = kp(5), a = kp(2)
        let oldGrant = try Authority.issueFS(gs, grantee: a.publicKey, resource: RES, rights: .init(3))
        XCTAssertEqual(try Authority.verifyChain([oldGrant], resource: RES, fsRoot: g, now: 1000), Authority.RightSet(3))
        let rr = try Authority.makeReroot(recovery, resource: RES, newRoot: n, effectiveEpoch: 1)
        let cur = Authority.currentRoot(RES, recoveryPublic: recovery.publicKey, genesisRoot: g, reroots: [rr])
        XCTAssertEqual(cur, n)
        XCTAssertThrowsError(try Authority.verifyChain([oldGrant], resource: RES, fsRoot: cur, now: 1000))  // old retired
        let newGrant = try Authority.issueFS(ns, grantee: a.publicKey, resource: RES, rights: .init(3))
        XCTAssertEqual(try Authority.verifyChain([newGrant], resource: RES, fsRoot: cur, now: 1000), Authority.RightSet(3))
    }
}
