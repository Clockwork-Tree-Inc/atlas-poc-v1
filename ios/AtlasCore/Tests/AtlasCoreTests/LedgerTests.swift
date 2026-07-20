import XCTest
@testable import AtlasCore

/// Native-logic parity for individual ledgers + global anchoring + per-conversation choice
/// (TRUST_LAYER.md #8/#9) — kept in lockstep with backend/tests/test_ledger.py.
final class LedgerTests: XCTestCase {

    private func rnd(_ n: Int = 32) -> Data { Primitives.randomBytes(n) }

    func testMerkleInclusionEveryIndex() {
        for n in [1, 2, 3, 5, 8, 9, 17] {
            let leaves = (0..<n).map { _ in rnd() }
            let root = Merkle.root(leaves)
            for i in 0..<n {
                let proof = Merkle.inclusionProof(leaves, index: i)
                XCTAssertTrue(Merkle.verifyInclusion(leaves[i], proof: proof, root: root))
                XCTAssertFalse(Merkle.verifyInclusion(rnd(), proof: proof, root: root))
            }
        }
    }

    func testCommitHidesAndBinds() {
        let content = Data("hello world".utf8)
        let (c1, o1) = LedgerCommit.commit(content)
        let (c2, o2) = LedgerCommit.commit(content)
        XCTAssertNotEqual(o1, o2); XCTAssertNotEqual(c1, c2)          // hiding
        XCTAssertEqual(LedgerCommit.commit(content, opening: o1).commitment, c1)  // binding
        XCTAssertNotEqual(LedgerCommit.commit(Data("other".utf8), opening: o1).commitment, c1)
    }

    func testIndividualLedgerInclusion() {
        let led = IndividualLedger(ownerID: Data("space-1".utf8))
        var commits: [Data] = []
        for i in 0..<6 {
            let (c, _) = LedgerCommit.commit(Data("m\(i)".utf8))
            led.append(c); commits.append(c)
        }
        for (i, c) in commits.enumerated() {
            let proof = led.prove(i)
            XCTAssertEqual(proof.commitment, c)
            XCTAssertEqual(proof.root, led.root)
            XCTAssertTrue(proof.verify())
        }
    }

    func testGlobalAnchorChainAndLookup() throws {
        let g = GlobalAnchorLog()
        let led = IndividualLedger(ownerID: Data("user-A".utf8))
        led.append(LedgerCommit.commit(Data("m0".utf8)).commitment)
        let r1 = led.root
        let rec1 = try g.anchor(ownerID: Data("user-A".utf8), root: r1, drandRound: Data([0,0,0,0,0,0,0,1]))
        led.append(LedgerCommit.commit(Data("m1".utf8)).commitment)
        let r2 = led.root
        try g.anchor(ownerID: Data("user-A".utf8), root: r2, drandRound: Data([0,0,0,0,0,0,0,2]))
        XCTAssertTrue(g.verifyChain())
        XCTAssertEqual(g.latestRoot(Data("user-A".utf8)), r2)
        XCTAssertTrue(g.isAnchored(ownerID: Data("user-A".utf8), root: r1))
        XCTAssertNil(g.latestRoot(Data("unknown".utf8)))
        XCTAssertEqual(rec1.prevHash, GlobalAnchorLog.genesis)
    }

    func testAccountableProvableDeniableNot() throws {
        let led = IndividualLedger(ownerID: Data("user-A".utf8))
        let g = GlobalAnchorLog()

        // DENIABLE commits nothing
        XCTAssertNil(ConversationLedger.recordMessage(led, mode: .deniable, content: Data("off record".utf8)))
        XCTAssertEqual(led.count, 0)

        // ACCOUNTABLE commits + is provable later
        let content = Data("I agree to the terms.".utf8)
        guard let msg = ConversationLedger.recordMessage(led, mode: .accountable, content: content) else {
            return XCTFail("accountable should return a receipt")
        }
        XCTAssertEqual(led.count, 1)
        try g.anchor(ownerID: led.ownerID, root: led.root, drandRound: Data([0,0,0,0,0,0,0,7]))

        let proof = ConversationLedger.proveMessage(led, msg: msg, content: content)
        XCTAssertTrue(proof.verify())
        XCTAssertTrue(g.isAnchored(ownerID: led.ownerID, root: proof.inclusion.root))
        // forged content does not verify
        let bad = ConversationLedger.proveMessage(led, msg: msg, content: Data("I never agreed.".utf8))
        XCTAssertFalse(bad.verify())
    }
}
