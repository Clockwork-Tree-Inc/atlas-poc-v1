import Foundation

/// Market (receipt-gated review) + Feed (endorsements, author-curated top-3) — mirrors
/// `backend/atlas/spaces/market.py` byte-for-byte. Not new crypto: HybridSign signatures over
/// domain-separated, length-prefixed bodies (same discipline as the authority engine).
///
/// MARKET — "a review is a receipt." No verified purchase → no review, PROVABLY. A `Review` is valid
/// ONLY when backed by a seller-signed `Receipt` binding THIS reviewer to a purchase of THIS item.
/// FEED — `Endorsement`s are signed vouches the platform SURFACES but never ranks; the author curates
/// their own `top3` (user choice, no algorithm).
extension Spaces {

    fileprivate static let receiptDomain = Data("atlas/market/receipt/v1".utf8)
    fileprivate static let reviewDomain = Data("atlas/market/review/v1".utf8)
    fileprivate static let endorseDomain = Data("atlas/market/endorse/v1".utf8)
    fileprivate static let reviewContentDomain = Data("atlas/market/review-content".utf8)

    /// Length-prefix (4-byte big-endian) — matches Python `_lp`.
    fileprivate static func lp(_ b: Data) -> Data {
        var n = UInt32(b.count).bigEndian
        var out = Data()
        withUnsafeBytes(of: &n) { out.append(contentsOf: $0) }
        out.append(b)
        return out
    }
    fileprivate static func u32(_ v: Int) -> Data {
        var n = UInt32(v).bigEndian; return withUnsafeBytes(of: &n) { Data($0) }
    }
    fileprivate static func u64(_ v: UInt64) -> Data {
        var n = v.bigEndian; return withUnsafeBytes(of: &n) { Data($0) }
    }

    // ----------------------------------------------------------------- market: receipt + review
    /// Seller-signed proof that `buyer` (a verified human) purchased `item`. The entry ticket to a
    /// review — a review with no receipt is not a review.
    public struct Receipt {
        public var seller: HybridSign.PublicKey
        public var buyer: HybridSign.PublicKey
        public var item: Data
        public var epoch: UInt64
        public var sig: Data = Data()

        public init(seller: HybridSign.PublicKey, buyer: HybridSign.PublicKey, item: Data,
                    epoch: UInt64, sig: Data = Data()) {
            self.seller = seller; self.buyer = buyer; self.item = item; self.epoch = epoch; self.sig = sig
        }

        func body() -> Data {
            receiptDomain + lp(seller.encode()) + lp(buyer.encode()) + lp(item) + u64(epoch)
        }
    }

    public static func issueReceipt(_ sellerKp: HybridSign.Keypair, buyer: HybridSign.PublicKey,
                                    item: Data, epoch: UInt64) throws -> Receipt {
        var r = Receipt(seller: sellerKp.publicKey, buyer: buyer, item: item, epoch: epoch)
        r.sig = try HybridSign.sign(sellerKp, r.body())
        return r
    }

    /// A reviewer-signed rating of `item`. Valid ONLY with a matching Receipt (see verifyReview).
    public struct Review {
        public var reviewer: HybridSign.PublicKey
        public var item: Data
        public var rating: Int
        public var contentHash: Data
        public var epoch: UInt64
        public var sig: Data = Data()

        public init(reviewer: HybridSign.PublicKey, item: Data, rating: Int, contentHash: Data,
                    epoch: UInt64, sig: Data = Data()) {
            self.reviewer = reviewer; self.item = item; self.rating = rating
            self.contentHash = contentHash; self.epoch = epoch; self.sig = sig
        }

        func body() -> Data {
            reviewDomain + lp(reviewer.encode()) + lp(item) + u32(rating) + lp(contentHash) + u64(epoch)
        }
    }

    public static func writeReview(_ reviewerKp: HybridSign.Keypair, item: Data, rating: Int,
                                   content: Data, epoch: UInt64) throws -> Review {
        var r = Review(reviewer: reviewerKp.publicKey, item: item, rating: rating,
                       contentHash: Primitives.H(reviewContentDomain, content), epoch: epoch)
        r.sig = try HybridSign.sign(reviewerKp, r.body())
        return r
    }

    /// NO PURCHASE → NO REVIEW. Valid iff: the reviewer signed it; the seller signed a receipt for
    /// THIS item purchased by THIS reviewer. Can't be faked (no reviewer key) or bought (no receipt).
    /// The MARKET REQUIRES A REAL-PERSON PSEUDONYM: a marketplace runs in a VERIFIED_PERSON space, and
    /// passing `isVerifiedHuman` enforces that the reviewer is a personhood-backed pseudonym (one real
    /// accountable human, real-ID hidden) — a verified purchase BY a verified person, not sockpuppets.
    public static func verifyReview(_ review: Review, _ receipt: Receipt,
                                    sellerPublic: HybridSign.PublicKey,
                                    isVerifiedHuman: ((Data) -> Bool)? = nil) -> Bool {
        guard HybridSign.verify(review.reviewer, review.body(), review.sig) else { return false }
        guard HybridSign.verify(sellerPublic, receipt.body(), receipt.sig) else { return false }
        guard receipt.item == review.item else { return false }
        guard receipt.buyer.encode() == review.reviewer.encode() else { return false }
        if let check = isVerifiedHuman, !check(review.reviewer.encode()) { return false }
        return true
    }

    // ----------------------------------------------------------------- feed: endorsements + top3
    /// A signed endorsement by `endorser` over `target` (a post commitment or author handle). The
    /// platform surfaces it verifiably; it never ranks.
    public struct Endorsement {
        public var endorser: HybridSign.PublicKey
        public var target: Data
        public var epoch: UInt64
        public var sig: Data = Data()

        public init(endorser: HybridSign.PublicKey, target: Data, epoch: UInt64, sig: Data = Data()) {
            self.endorser = endorser; self.target = target; self.epoch = epoch; self.sig = sig
        }

        func body() -> Data { endorseDomain + lp(endorser.encode()) + lp(target) + u64(epoch) }
    }

    public static func endorse(_ endorserKp: HybridSign.Keypair, target: Data,
                               epoch: UInt64) throws -> Endorsement {
        var e = Endorsement(endorser: endorserKp.publicKey, target: target, epoch: epoch)
        e.sig = try HybridSign.sign(endorserKp, e.body())
        return e
    }

    public static func verifyEndorsement(_ e: Endorsement) -> Bool {
        HybridSign.verify(e.endorser, e.body(), e.sig)
    }

    /// The AUTHOR curates which endorsements to feature — user choice, no algorithm. Returns up to 3
    /// VALID endorsements whose endorser (by encoded key) is in `chosen`, in the author's order.
    /// Invalid or unchosen endorsements are dropped; nothing is ranked by the platform.
    public static func top3(_ endorsements: [Endorsement], chosen: [Data]) -> [Endorsement] {
        var valid: [Data: Endorsement] = [:]
        for e in endorsements where verifyEndorsement(e) {
            valid[e.endorser.encode()] = e   // last-wins, matching Python's dict comprehension
        }
        var out: [Endorsement] = []
        var seen = Set<Data>()
        for enc in chosen {
            if let e = valid[enc], !seen.contains(enc) {
                out.append(e); seen.insert(enc)
            }
            if out.count == 3 { break }
        }
        return out
    }
}
