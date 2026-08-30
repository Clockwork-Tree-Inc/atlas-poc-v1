import Foundation

/// Market storefront — where every product LIVES and TRANSACTS. Swift parity with
/// `backend/atlas/storefront.py` (Python reference of record).
///
/// There is no "published but not in the market" mode: every product lives in the market as a
/// storefront listing — a Merchandising card (cover/blurb/description/preview = the author's chosen
/// exposure) shown to shoppers, with the FULL product GATED behind free / buy / request-access, or a
/// paid Subscription covering the creator's media. Signed under the persona handle (unlinkable);
/// content stays on the author's device/node.

public enum AccessMode: String, Codable, Sendable { case free, buy, request }

public enum StorefrontError: Error { case badListing, accessDenied }

public struct Merchandising: Codable, Equatable, Sendable {
    public var cover: String
    public var blurb: String
    public var description: String
    public var preview: String
    public var gallery: [String]
    public init(cover: String = "", blurb: String = "", description: String = "",
                preview: String = "", gallery: [String] = []) {
        self.cover = cover; self.blurb = blurb; self.description = description
        self.preview = preview; self.gallery = gallery
    }
}

public struct MarketListing {
    public let workID: Data
    public let author: String            // persona handle (hex)
    public let publicKey: HybridSign.PublicKey
    public let title: String
    public let tags: [String]
    public let license: String
    public let priceAtlas: Int
    public let access: AccessMode
    public let merch: Merchandising
    public let fullContentRef: String    // gated — released only by openFull
    public var sig: Data = Data()

    public func id() -> Data {
        Primitives.H(Data("atlas/market-listing/id".utf8), workID, Data(author.utf8))
    }

    public func body() -> Data {
        Primitives.H(Data("atlas/market-listing/v1".utf8), workID, Data(author.utf8),
                     Data(title.utf8), Data(tags.joined(separator: " ").utf8), Data(license.utf8),
                     Data(String(priceAtlas).utf8), Data(access.rawValue.utf8),
                     Data(merch.cover.utf8), Data(merch.blurb.utf8), Data(merch.description.utf8),
                     Data(merch.preview.utf8), Data(merch.gallery.joined(separator: "|").utf8),
                     Data(fullContentRef.utf8))
    }
}

public enum Storefront {
    /// List a work on the market under the signer's persona handle.
    public static func listOnMarket(workID: Data, title: String, tags: [String], license: String,
                                    priceAtlas: Int, access: AccessMode, merch: Merchandising,
                                    fullContentRef: String, signer: HybridSign.Keypair) throws -> MarketListing {
        var l = MarketListing(workID: workID, author: handleOf(signer.publicKey.encode()).hex(),
                              publicKey: signer.publicKey, title: title, tags: tags, license: license,
                              priceAtlas: priceAtlas, access: access, merch: merch,
                              fullContentRef: fullContentRef)
        l.sig = try HybridSign.sign(signer, l.body())
        return l
    }

    public static func verify(_ l: MarketListing) -> Bool {
        handleOf(l.publicKey.encode()).hex() == l.author && HybridSign.verify(l.publicKey, l.body(), l.sig)
    }

    // MARK: acquisition — the single market gate

    public struct AccessGrant {
        public let listingID: Data
        public let requester: Data
        public let grantor: HybridSign.PublicKey
        public let sig: Data
        public func body() -> Data {
            Primitives.H(Data("atlas/market-access/v1".utf8), listingID, requester)
        }
    }

    public static func grantAccess(author: HybridSign.Keypair, listing: MarketListing,
                                   requester: Data) throws -> AccessGrant {
        let body = Primitives.H(Data("atlas/market-access/v1".utf8), listing.id(), requester)
        return AccessGrant(listingID: listing.id(), requester: requester,
                           grantor: author.publicKey, sig: try HybridSign.sign(author, body))
    }

    /// A paid media subscription — a time-bounded standing grant over a creator's media.
    public struct Subscription {
        public let subscriber: Data
        public let scope: String          // creator handle (hex)
        public let expires: Int
        public let issuer: HybridSign.PublicKey
        public let sig: Data
        public func body() -> Data {
            Primitives.H(Data("atlas/subscription/v1".utf8), subscriber, Data(scope.utf8),
                         Data(String(expires).utf8))
        }
    }

    public static func issueSubscription(issuer: HybridSign.Keypair, subscriber: Data,
                                         scope: String, expires: Int) throws -> Subscription {
        let body = Primitives.H(Data("atlas/subscription/v1".utf8), subscriber, Data(scope.utf8),
                                Data(String(expires).utf8))
        return Subscription(subscriber: subscriber, scope: scope, expires: expires,
                            issuer: issuer.publicKey, sig: try HybridSign.sign(issuer, body))
    }

    public static func subscriptionCovers(_ s: Subscription, listing: MarketListing,
                                          requester: Data, now: Int) -> Bool {
        s.subscriber == requester && s.expires > now && s.scope == listing.author
            && s.issuer.encode() == listing.publicKey.encode()
            && HybridSign.verify(s.issuer, s.body(), s.sig)
    }

    /// The one gate: FREE opens for anyone; otherwise a per-item grant (buy/request) OR a valid
    /// subscription covering this creator's media. Nothing else releases the ref.
    public static func openFull(_ listing: MarketListing, requester: Data,
                                grant: AccessGrant? = nil, subscription: Subscription? = nil,
                                now: Int = 0) throws -> String {
        if listing.access == .free { return listing.fullContentRef }
        if let g = grant, g.listingID == listing.id(), g.requester == requester,
           g.grantor.encode() == listing.publicKey.encode(),
           HybridSign.verify(g.grantor, g.body(), g.sig) {
            return listing.fullContentRef
        }
        if let s = subscription, subscriptionCovers(s, listing: listing, requester: requester, now: now) {
            return listing.fullContentRef
        }
        throw StorefrontError.accessDenied
    }

    // MARK: shareable link — where the item lives to be seen and picked

    public static let marketLinkBase = "https://atlas.id/m/"

    public static func marketLink(_ listingID: Data) -> String {
        marketLinkBase + listingID.hex()
    }

    public static func parseMarketLink(_ url: String) -> Data? {
        for base in [marketLinkBase, "atlas://m/"] where url.hasPrefix(base) {
            return Data(hexString: String(url.dropFirst(base.count)).trimmingCharacters(in: CharacterSet(charactersIn: "/")))
        }
        return nil
    }
}

extension Data {
    func hex() -> String { map { String(format: "%02x", $0) }.joined() }
    init?(hexString: String) {
        guard hexString.count % 2 == 0 else { return nil }
        var out = Data()
        var idx = hexString.startIndex
        while idx < hexString.endIndex {
            let next = hexString.index(idx, offsetBy: 2)
            guard let b = UInt8(hexString[idx..<next], radix: 16) else { return nil }
            out.append(b); idx = next
        }
        self = out
    }
}
