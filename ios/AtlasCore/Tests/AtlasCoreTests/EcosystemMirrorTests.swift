import XCTest
@testable import AtlasCore

/// Swift mirrors of storefront.py / feed.py / participant.py — the load-bearing properties:
/// the market gate (free/grant/subscription, no side door), feed tiers (follow=free,
/// subscribe=paid), and verification-not-authority (trust binds to the KEY).
final class EcosystemMirrorTests: XCTestCase {

    private func seller() throws -> (HybridSign.Keypair, String) {
        let kp = try HybridSign.keypair(fromSeed: Primitives.randomBytes(32))
        return (kp, handleOf(kp.publicKey.encode()).hex())
    }

    private func listing(_ kp: HybridSign.Keypair, access: AccessMode) throws -> MarketListing {
        try Storefront.listOnMarket(workID: Data("book1".utf8), title: "Tide Atlas",
                                    tags: ["tide"], license: "content:quote", priceAtlas: 30,
                                    access: access,
                                    merch: Merchandising(blurb: "Every tide, mapped", preview: "vault://ch1"),
                                    fullContentRef: "vault://full", signer: kp)
    }

    func testMarketGateFreeGrantSubscriptionNoSideDoor() throws {
        let (kp, handle) = try seller()
        let buyer = Data("buyer".utf8)
        // free opens for anyone
        let free = try listing(kp, access: .free)
        XCTAssertEqual(try Storefront.openFull(free, requester: buyer), "vault://full")
        // gated: no grant -> denied; author grant bound to (listing, requester) -> opens
        let paid = try listing(kp, access: .buy)
        XCTAssertTrue(Storefront.verify(paid))
        XCTAssertThrowsError(try Storefront.openFull(paid, requester: buyer))
        let grant = try Storefront.grantAccess(author: kp, listing: paid, requester: buyer)
        XCTAssertEqual(try Storefront.openFull(paid, requester: buyer, grant: grant), "vault://full")
        XCTAssertThrowsError(try Storefront.openFull(paid, requester: Data("bob".utf8), grant: grant))
        // subscription covering the creator opens without a per-item grant; expiry closes it
        let sub = try Storefront.issueSubscription(issuer: kp, subscriber: buyer, scope: handle, expires: 1000)
        XCTAssertEqual(try Storefront.openFull(paid, requester: buyer, subscription: sub, now: 100), "vault://full")
        XCTAssertThrowsError(try Storefront.openFull(paid, requester: buyer, subscription: sub, now: 2000))
        // market link resolves to the same listing id
        XCTAssertEqual(Storefront.parseMarketLink(Storefront.marketLink(paid.id())), paid.id())
    }

    func testFeedFollowFreeSubscribePaid() throws {
        let (kp, author) = try seller()
        let viewer = Data("viewer".utf8)
        let feed = Feed()
        feed.follow(viewer, author: author)
        try feed.post(Feed.makePost(author: kp, ts: 1, caption: "free note"))
        try feed.post(Feed.makePost(author: kp, ts: 2, caption: "paid deep-dive", tier: .paid))
        XCTAssertEqual(feed.timeline(viewer).map { $0.caption }, ["free note"])
        let sub = try Storefront.issueSubscription(issuer: kp, subscriber: viewer, scope: author, expires: 100)
        XCTAssertEqual(feed.timeline(viewer, subscriptions: [sub], now: 10).map { $0.caption },
                       ["paid deep-dive", "free note"])
        // forged post rejected
        var bad = try Feed.makePost(author: kp, ts: 3, caption: "ok")
        bad.sig = Data(repeating: 0, count: 8)
        XCTAssertThrowsError(try feed.post(bad))
    }

    func testVerificationNotAuthorityTrustBindsToKey() throws {
        let (realBoard, _) = try seller()
        let (impostor, _) = try seller()
        let (subjKP, _) = try seller()
        let handle = handleOf(subjKP.publicKey.encode())
        let p = ParticipantProfile(handle: handle, publicKey: subjKP.publicKey, entityClass: .individual)
        try p.goPublic(displayName: "Dr Bob")
        // impostor uses the SAME display name; signature is valid but the KEY isn't trusted
        try p.hold(issueAttestation(authority: impostor, authorityName: "Medical Board",
                                    subject: handle, claim: "licensed-physician"))
        XCTAssertFalse(presents(p, claim: "licensed-physician",
                                trustedAuthorityKeys: [realBoard.publicKey.encode()]))
        try p.hold(issueAttestation(authority: realBoard, authorityName: "Medical Board",
                                    subject: handle, claim: "licensed-physician"))
        XCTAssertTrue(presents(p, claim: "licensed-physician",
                               trustedAuthorityKeys: [realBoard.publicKey.encode()]))
        XCTAssertTrue(p.isVerified)
        // an attestation about someone else can't be held
        XCTAssertThrowsError(try p.hold(issueAttestation(authority: realBoard, authorityName: "X",
                                                         subject: Data("other".utf8), claim: "c")))
    }
}
