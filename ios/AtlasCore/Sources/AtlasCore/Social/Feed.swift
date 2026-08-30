import Foundation

/// Feed — a follow-based newsletter/Substack for all media. Swift parity with
/// `backend/atlas/feed.py` (Python reference of record).
///
/// Two independent relationships: FOLLOW (free) puts an author's FREE posts in your timeline;
/// SUBSCRIBE (paid — Storefront.Subscription) additionally unlocks their PAID posts (and, in the
/// market, their gated media). A post may carry a market link to acquire a product; the feed shows
/// previews + links only — acquiring gated media still routes through the market gate.

public enum PostTier: String, Codable, Sendable { case free, paid }

public enum FeedError: Error { case badPost }

public struct FeedPost: Identifiable {
    public let author: String            // persona handle (hex)
    public let publicKey: HybridSign.PublicKey
    public let ts: Int
    public let tier: PostTier
    public let caption: String
    public let media: [String]
    public let marketRef: String
    public var sig: Data = Data()

    public var id: Data { Primitives.H(Data("atlas/feed-post/id".utf8), publicKey.encode(), body()) }

    public func body() -> Data {
        Primitives.H(Data("atlas/feed-post/v1".utf8), Data(author.utf8), Data(String(ts).utf8),
                     Data(tier.rawValue.utf8), Data(caption.utf8),
                     Data(media.joined(separator: "|").utf8), Data(marketRef.utf8))
    }
}

public final class Feed {
    private var posts: [String: [FeedPost]] = [:]          // author hex -> posts
    private var following: [Data: Set<String>] = [:]       // follower handle -> authors
    public init() {}

    public static func makePost(author: HybridSign.Keypair, ts: Int, caption: String,
                                tier: PostTier = .free, media: [String] = [],
                                marketRef: String = "") throws -> FeedPost {
        var p = FeedPost(author: handleOf(author.publicKey.encode()).hex(), publicKey: author.publicKey,
                         ts: ts, tier: tier, caption: caption, media: media, marketRef: marketRef)
        p.sig = try HybridSign.sign(author, p.body())
        return p
    }

    public static func verify(_ p: FeedPost) -> Bool {
        handleOf(p.publicKey.encode()).hex() == p.author && HybridSign.verify(p.publicKey, p.body(), p.sig)
    }

    public func post(_ p: FeedPost) throws {
        guard Feed.verify(p) else { throw FeedError.badPost }
        posts[p.author, default: []].append(p)
    }

    public func follow(_ follower: Data, author: String) { following[follower, default: []].insert(author) }
    public func unfollow(_ follower: Data, author: String) { following[follower]?.remove(author) }
    public func followingSet(_ follower: Data) -> Set<String> { following[follower] ?? [] }

    /// Merged newest-first timeline: FREE posts from everyone followed; a PAID post only with a
    /// valid subscription covering that author.
    public func timeline(_ viewer: Data, subscriptions: [Storefront.Subscription] = [],
                         now: Int = 0, limit: Int = 50) -> [FeedPost] {
        var out: [FeedPost] = []
        for author in following[viewer] ?? [] {
            for p in posts[author] ?? [] {
                if p.tier == .free { out.append(p); continue }
                let covered = subscriptions.contains { s in
                    s.subscriber == viewer && s.expires > now && s.scope == author
                        && s.issuer.encode() == p.publicKey.encode()
                        && HybridSign.verify(s.issuer, s.body(), s.sig)
                }
                if covered { out.append(p) }
            }
        }
        return Array(out.sorted { $0.ts > $1.ts }.prefix(limit))
    }
}
