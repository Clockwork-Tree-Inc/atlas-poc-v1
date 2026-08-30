import Foundation

/// Organization access gate + anti-ad SURFACING — Swift mirror of `backend/atlas/marketplace.py`.
/// Businesses pay a tithe to be ELIGIBLE + must pass conformance; but payment buys eligibility,
/// NEVER rank. The user's agent asks for a need; only genuine matches are returned, ranked by
/// relevance + verified-human review score (pull, not push; no ads; no pay-to-rank).
public enum Marketplace {

    public enum EntityClass: String {
        case individual, nonprofit, forProfit = "for_profit", agent
    }

    public struct Organization {
        public var handle: Data
        public var entityClass: EntityClass
        public var region: String
        public var conformant: Bool
        public var paid: Bool
        public init(handle: Data, entityClass: EntityClass, region: String,
                    conformant: Bool = false, paid: Bool = false) {
            self.handle = handle; self.entityClass = entityClass; self.region = region
            self.conformant = conformant; self.paid = paid
        }
    }

    /// The ACCESS GATE: eligible to surface only if PAID (membership active) AND conformant.
    public static func isSurfaceable(_ b: Organization) -> Bool { b.paid && b.conformant }

    public struct Listing {
        public var business: Data
        public var publicKey: HybridSign.PublicKey
        public var title: String
        public var tags: [String]
        public var priceAtlas: Int
        public var region: String
        public var sig: Data
        public init(business: Data, publicKey: HybridSign.PublicKey, title: String, tags: [String],
                    priceAtlas: Int, region: String, sig: Data = Data()) {
            self.business = business; self.publicKey = publicKey; self.title = title; self.tags = tags
            self.priceAtlas = priceAtlas; self.region = region; self.sig = sig
        }
        public func body() -> Data {
            Primitives.H(Data("atlas/listing".utf8), business, Data(title.utf8),
                         Data(tags.joined(separator: " ").utf8), Data(String(priceAtlas).utf8),
                         Data(region.utf8))
        }
        public func id() -> Data { Primitives.H(Data("atlas/listing/id".utf8), body()) }
    }

    public static func listItem(_ identity: Child, title: String, tags: [String], priceAtlas: Int,
                                region: String) throws -> Listing {
        var l = Listing(business: identity.handle, publicKey: identity.publicKey, title: title,
                        tags: tags, priceAtlas: priceAtlas, region: region)
        l.sig = try HybridSign.sign(identity.keypair, l.body())
        return l
    }

    public static func verifyListing(_ l: Listing) -> Bool {
        guard handleOf(l.publicKey.encode()) == l.business else { return false }
        return HybridSign.verify(l.publicKey, l.body(), l.sig)
    }

    private static func tokens(_ s: String) -> Set<String> {
        Set(s.lowercased().replacingOccurrences(of: ",", with: " ")
            .split(whereSeparator: { $0 == " " || $0 == "\n" || $0 == "\t" }).map(String.init))
    }

    /// The user's agent asks for what they NEED; return eligible, matching listings ranked by
    /// relevance + reviews. Payment/standing only GATES eligibility, never rank; only genuine
    /// matches are returned.
    public static func surface(query: String, region: String?, listings: [Listing],
                               businesses: [Organization], reviewNet: [Data: Int] = [:]) -> [Listing] {
        let biz = Dictionary(businesses.map { ($0.handle, $0) }, uniquingKeysWith: { a, _ in a })
        let q = tokens(query)
        var scored: [(rel: Int, rev: Int, idx: Int, listing: Listing)] = []
        for (i, l) in listings.enumerated() {
            guard let b = biz[l.business], isSurfaceable(b) else { continue }   // access gate
            if let region, l.region != region { continue }                      // region-scoped
            guard verifyListing(l) else { continue }
            let rel = q.intersection(tokens(l.title + " " + l.tags.joined(separator: " "))).count
            if rel == 0 { continue }                                            // no match -> not surfaced
            scored.append((rel, reviewNet[l.id()] ?? 0, i, l))
        }
        scored.sort { a, b in
            if a.rel != b.rel { return a.rel > b.rel }      // relevance first
            if a.rev != b.rev { return a.rev > b.rev }      // then reviews — NEVER payment
            return a.idx < b.idx                            // stable on full ties
        }
        return scored.map { $0.listing }
    }
}
