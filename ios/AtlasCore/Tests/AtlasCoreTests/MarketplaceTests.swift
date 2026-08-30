import XCTest
@testable import AtlasCore

/// Organization access gate + anti-ad surfacing (Swift), parity with `backend/atlas/marketplace.py`.
final class MarketplaceTests: XCTestCase {
    private func biz(_ name: String, region: String = "us", paid: Bool = true,
                     conformant: Bool = true) throws -> (Child, Marketplace.Organization) {
        let id = try IdentityTree.build(tskSeed: Primitives.randomBytes(32), sphincs: StubSphincs()).profile(name).identity
        return (id, Marketplace.Organization(handle: id.handle, entityClass: .forProfit, region: region,
                                         conformant: conformant, paid: paid))
    }

    func testListingBodyIdParityKAT() {
        let l = Marketplace.Listing(business: Data(count: 32),
                                    publicKey: (try! IdentityTree.build(tskSeed: Primitives.randomBytes(32),
                                                                        sphincs: StubSphincs()).child(.authorship)).publicKey,
                                    title: "boots", tags: ["hiking", "waterproof"], priceAtlas: 50, region: "us")
        func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
        // byte-identical to the Python reference body/id for these fixed inputs (business = 32 zero bytes)
        XCTAssertEqual(hex(l.body()), "3a86558148639c942e5529c340bf2050a7983bad987cd73048d490d98b9a785e")
        XCTAssertEqual(hex(l.id()), "608ab29fbb1e462064de44631d9a5aea56767b2e189e1d3869aca05fa198c86b")
    }

    func testAccessGateRequiresPaidAndConformant() throws {
        var (_, b) = try biz("shop")
        XCTAssertTrue(Marketplace.isSurfaceable(b))
        b.paid = false; XCTAssertFalse(Marketplace.isSurfaceable(b))
        b.paid = true; b.conformant = false; XCTAssertFalse(Marketplace.isSurfaceable(b))
    }

    func testSurfaceIsPullAndRelevanceRankedNotPayToRank() throws {
        let (gid, good) = try biz("boots")
        let (wid, weak) = try biz("candles")
        let g = try Marketplace.listItem(gid, title: "Waterproof hiking boots",
                                         tags: ["boots", "hiking", "waterproof"], priceAtlas: 50, region: "us")
        let w = try Marketplace.listItem(wid, title: "Scented candle", tags: ["candle", "home"], priceAtlas: 20, region: "us")
        XCTAssertTrue(Marketplace.verifyListing(g) && Marketplace.verifyListing(w))
        let out = Marketplace.surface(query: "hiking boots", region: "us", listings: [w, g], businesses: [good, weak])
        XCTAssertEqual(out.map { $0.id() }, [g.id()])   // best match only; non-matching candle not surfaced
    }

    func testUnpaidOrOutOfRegionExcluded() throws {
        let (aid, a) = try biz("a", region: "us")
        let (bid, b) = try biz("b", region: "us", paid: false)
        let la = try Marketplace.listItem(aid, title: "red boots", tags: ["boots"], priceAtlas: 10, region: "us")
        let lb = try Marketplace.listItem(bid, title: "blue boots", tags: ["boots"], priceAtlas: 10, region: "us")
        XCTAssertEqual(Marketplace.surface(query: "boots", region: "us", listings: [la, lb], businesses: [a, b]).map { $0.id() }, [la.id()])
        XCTAssertEqual(Marketplace.surface(query: "boots", region: "eu", listings: [la], businesses: [a]).count, 0)
    }

    func testReviewsBreakTiesNotPayment() throws {
        let (xid, x) = try biz("x")
        let (yid, y) = try biz("y")
        let lx = try Marketplace.listItem(xid, title: "boots", tags: ["boots"], priceAtlas: 10, region: "us")
        let ly = try Marketplace.listItem(yid, title: "boots", tags: ["boots"], priceAtlas: 10, region: "us")
        let out = Marketplace.surface(query: "boots", region: "us", listings: [lx, ly], businesses: [x, y],
                                      reviewNet: [ly.id(): 5, lx.id(): 1])
        XCTAssertEqual(out.map { $0.id() }, [ly.id(), lx.id()])   // higher-reviewed first (not payment)
    }

    func testForgedListingRejected() throws {
        let (rid, real) = try biz("real")
        let (aid, _) = try biz("atk")
        var l = try Marketplace.listItem(aid, title: "boots", tags: ["boots"], priceAtlas: 10, region: "us")
        l.business = real.handle                                 // claim someone else's handle
        XCTAssertFalse(Marketplace.verifyListing(l))
        XCTAssertEqual(Marketplace.surface(query: "boots", region: "us", listings: [l], businesses: [real]).count, 0)
        _ = rid
    }
}
