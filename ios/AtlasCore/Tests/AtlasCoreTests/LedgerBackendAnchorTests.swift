import XCTest
@testable import AtlasCore

/// Parity for the pluggable anchor backend (`backend/atlas/ledger/backend.py`) and the public
/// economics anchor (`backend/atlas/economy/anchor.py`). The anchor ROOTS are PUBLIC COMMITMENTS
/// both implementations must agree on for a future shared chain, so they are asserted
/// BYTE-IDENTICAL to KAT vectors generated from the Python reference.
final class LedgerBackendAnchorTests: XCTestCase {

    private func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
    private func round(_ v: UInt64) -> Data { var n = v.bigEndian; return withUnsafeBytes(of: &n) { Data($0) } }

    /// The exact IssuanceResult behind the issuance KAT: epoch=1, 10 persons @ activity 1,
    /// col=100, value=10000, tithe=0, supply=1_000_000, default params.
    private func katResult() throws -> IssuanceResult {
        let pool = PoLEPool()
        for i in 0..<10 {
            try pool.add(try collectPoLE(personTag: Data("p\(i)".utf8), epoch: 1,
                                         entropyCommit: Data("env".utf8), live: true, activityWeight: 1))
        }
        return try Policy.issue(pool, colIndex: 100, valueIndex: 10000, titheInflow: 0,
                                state: EconomyState(supply: 1_000_000))
    }

    // MARK: anchor roots — byte-identical to Python

    func testIssuanceRootMatchesPythonKAT() throws {
        let r = try katResult()
        // Sanity: the result matches the Python reference before we hash it.
        XCTAssertEqual(r.epoch, 1); XCTAssertEqual(r.persons, 10)
        XCTAssertEqual(r.ubiPerPerson, 100); XCTAssertEqual(r.ubiTotal, 1000)
        XCTAssertEqual(r.vrpTotal, 3500); XCTAssertEqual(r.foundationTotal, 500)
        XCTAssertEqual(r.titheUsed, 0); XCTAssertEqual(r.minted, 5000)
        XCTAssertEqual(r.newSupply, 1_005_000); XCTAssertTrue(r.controls.isEmpty)
        XCTAssertEqual(hex(EconomyAnchor.issuanceRoot(r)),
                       "cdaaf3ad82fc8ab6463029e52a55b5c52856d9631bd2208acc7a7d4a32779de6")
    }

    func testGovernanceRootMatchesPythonKAT() {
        XCTAssertEqual(hex(EconomyAnchor.governanceRoot(epoch: 7, colIndex: 120, valueIndex: 8000)),
                       "ac08ad58e20384c2999a99c23a1ab229f4d990199fa2ca19d7b02189214db17a")
    }

    // MARK: LocalBackend — over the Swift GlobalAnchor.Log

    func testLocalBackendPublishLatestRoundtrip() throws {
        let backend = LocalBackend()
        let owner = Data("atlas/economy/supply".utf8)
        let root = Data("root-one".utf8)
        let receipt = try backend.publish(ownerID: owner, root: root, epochRound: round(1))
        XCTAssertEqual(receipt.anchoredRoot, root)
        XCTAssertEqual(backend.latest(ownerID: owner), root)
        // Second, later round updates latest.
        let root2 = Data("root-two".utf8)
        _ = try backend.publish(ownerID: owner, root: root2, epochRound: round(5))
        XCTAssertEqual(backend.latest(ownerID: owner), root2)
        XCTAssertNil(backend.latest(ownerID: Data("unknown".utf8)))
    }

    func testLocalBackendRejectsNonMonotonicRound() throws {
        let backend = LocalBackend()
        let owner = Data("owner".utf8)
        _ = try backend.publish(ownerID: owner, root: Data("a".utf8), epochRound: round(5))
        XCTAssertThrowsError(try backend.publish(ownerID: owner, root: Data("b".utf8), epochRound: round(2))) {
            XCTAssertEqual($0 as? GlobalAnchor.AnchorError, .backdatedRound)
        }
    }

    // MARK: ChainBackend — stub throws

    func testChainBackendPublishThrows() {
        let backend = ChainBackend()
        XCTAssertThrowsError(try backend.publish(ownerID: Data("s".utf8), root: Data("r".utf8),
                                                 epochRound: round(1))) {
            XCTAssertEqual($0 as? ChainBackendError, .notBuilt)
        }
        XCTAssertThrowsError(try backend.latest(ownerID: Data("s".utf8))) {
            XCTAssertEqual($0 as? ChainBackendError, .notBuilt)
        }
    }

    // MARK: anchor_* store the matching root under the right stream id

    func testAnchorIssuanceStoresRootUnderSupplyStream() throws {
        let backend = LocalBackend()
        let r = try katResult()
        let receipt = try EconomyAnchor.anchorIssuance(backend, r, epochRound: round(1))
        XCTAssertEqual(receipt.ownerID, EconomyAnchor.economySupply)
        XCTAssertEqual(receipt.anchoredRoot, EconomyAnchor.issuanceRoot(r))
        XCTAssertEqual(backend.latest(ownerID: EconomyAnchor.economySupply), EconomyAnchor.issuanceRoot(r))
    }

    func testAnchorGovernanceStoresRootUnderGovernanceStream() throws {
        let backend = LocalBackend()
        let receipt = try EconomyAnchor.anchorGovernance(backend, epoch: 7, colIndex: 120,
                                                         valueIndex: 8000, epochRound: round(1))
        XCTAssertEqual(receipt.ownerID, EconomyAnchor.economyGovernance)
        let expected = EconomyAnchor.governanceRoot(epoch: 7, colIndex: 120, valueIndex: 8000)
        XCTAssertEqual(receipt.anchoredRoot, expected)
        XCTAssertEqual(backend.latest(ownerID: EconomyAnchor.economyGovernance), expected)
    }

    func testAnchorTransparencyStoresHeadUnderTransparencyStream() throws {
        let backend = LocalBackend()
        let ledger = Transparency.TransparencyLedger()
        try ledger.registerBusiness("acme", identified: true)
        try ledger.record(business: "acme", kind: "sale", amount: 10, fee: 1,
                          counterparty: "cust", epoch: 1)
        let receipt = try EconomyAnchor.anchorTransparency(backend, ledger, epochRound: round(1))
        XCTAssertEqual(receipt.ownerID, EconomyAnchor.economyTransparency)
        XCTAssertEqual(receipt.anchoredRoot, ledger.head())
        XCTAssertEqual(backend.latest(ownerID: EconomyAnchor.economyTransparency), ledger.head())
    }
}
