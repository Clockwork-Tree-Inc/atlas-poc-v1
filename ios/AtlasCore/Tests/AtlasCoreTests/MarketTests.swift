import XCTest
@testable import AtlasCore

/// Market (receipt-gated review) + Feed (author-curated top-3) — mirrors `backend/tests/test_market.py`.
final class MarketTests: XCTestCase {

    private func kp(_ n: UInt8) -> HybridSign.Keypair {
        try! HybridSign.keypair(fromSeed: Data(repeating: n, count: 32))
    }
    private lazy var seller = kp(1)
    private lazy var buyer = kp(2)
    private lazy var other = kp(3)
    private let item = Data("widget-42".utf8)

    // ------------------------------------------------------------------- market
    func testReviewWithMatchingReceiptVerifies() throws {
        let receipt = try Spaces.issueReceipt(seller, buyer: buyer.publicKey, item: item, epoch: 1)
        let review = try Spaces.writeReview(buyer, item: item, rating: 5, content: Data("great".utf8), epoch: 2)
        XCTAssertTrue(Spaces.verifyReview(review, receipt, sellerPublic: seller.publicKey))
    }

    func testNoPurchaseNoReview() throws {
        // OTHER never bought ITEM — presenting BUYER's receipt doesn't validate OTHER's review.
        let receiptForBuyer = try Spaces.issueReceipt(seller, buyer: buyer.publicKey, item: item, epoch: 1)
        let astroturf = try Spaces.writeReview(other, item: item, rating: 5, content: Data("fake".utf8), epoch: 2)
        XCTAssertFalse(Spaces.verifyReview(astroturf, receiptForBuyer, sellerPublic: seller.publicKey))
    }

    func testReviewForWrongItemRejected() throws {
        let receipt = try Spaces.issueReceipt(seller, buyer: buyer.publicKey, item: Data("other".utf8), epoch: 1)
        let review = try Spaces.writeReview(buyer, item: item, rating: 5, content: Data("x".utf8), epoch: 2)
        XCTAssertFalse(Spaces.verifyReview(review, receipt, sellerPublic: seller.publicKey))
    }

    func testForgedReceiptRejected() throws {
        let receipt = try Spaces.issueReceipt(other, buyer: buyer.publicKey, item: item, epoch: 1)  // not the seller
        let review = try Spaces.writeReview(buyer, item: item, rating: 5, content: Data("x".utf8), epoch: 2)
        XCTAssertFalse(Spaces.verifyReview(review, receipt, sellerPublic: seller.publicKey))
    }

    func testTamperedReviewRejected() throws {
        let receipt = try Spaces.issueReceipt(seller, buyer: buyer.publicKey, item: item, epoch: 1)
        var review = try Spaces.writeReview(buyer, item: item, rating: 5, content: Data("x".utf8), epoch: 2)
        review.rating = 1                                                          // tamper after signing
        XCTAssertFalse(Spaces.verifyReview(review, receipt, sellerPublic: seller.publicKey))
    }

    // ------------------------------------------------------------------- feed / endorsements
    func testEndorseAndVerify() throws {
        var e = try Spaces.endorse(kp(10), target: Data("post-1".utf8), epoch: 1)
        XCTAssertTrue(Spaces.verifyEndorsement(e))
        e.epoch = 999                                                              // tamper
        XCTAssertFalse(Spaces.verifyEndorsement(e))
    }

    func testTop3IsAuthorCuratedAndCapped() throws {
        let es = try [10, 11, 12, 13].map { try Spaces.endorse(kp(UInt8($0)), target: Data("post-1".utf8), epoch: 1) }
        let chosen = [12, 10, 13, 11].map { kp(UInt8($0)).publicKey.encode() }     // 4 chosen, capped to 3
        let featured = Spaces.top3(es, chosen: chosen)
        XCTAssertEqual(featured.map { $0.endorser.encode() }, Array(chosen.prefix(3)))
    }

    func testTop3DropsInvalidAndUnchosen() throws {
        let good = try Spaces.endorse(kp(10), target: Data("p".utf8), epoch: 1)
        let forged = Spaces.Endorsement(endorser: kp(11).publicKey, target: Data("p".utf8), epoch: 1)  // unsigned
        let featured = Spaces.top3([good, forged],
                                   chosen: [kp(11).publicKey.encode(), kp(10).publicKey.encode()])
        XCTAssertEqual(featured.map { $0.endorser.encode() }, [kp(10).publicKey.encode()])  // forged dropped
    }
}
