import Foundation

/// The librarian: retrieval + citation over authored works (mirrors
/// `backend/atlas/ai/librarian.py`). Atlas AI is a LIBRARIAN, not a ghostwriter — it SURFACES
/// known authored things, CITES them exactly, and routes you to PURCHASE unowned ones. It never
/// launders authored work into an opaque generated answer.
///
/// Same engine at every tier over the right corpus: PHONE = your on-device vault; NODE = your own
/// computer-grade private corpus; SERVER = the public commons register. This on-device version
/// runs the phone tier. Ranking logic is faithful to the Python reference.

/// Licenses that make a work OPEN — usable freely (still attributed), no purchase.
private let openLicenses: Set<String> = [
    "agpl", "agpl-3.0", "cc-by", "cc-by-sa", "cc0", "public-domain", "open",
]

/// The fail-safe default: a work whose license is unknown/absent is ALL RIGHTS RESERVED — not open,
/// and not usable even at price 0. License-by-default (see Library.swift) stamps this so a plugged-in
/// library can never make a work accidentally free by omitting its license.
private let reservedLicenses: Set<String> = ["all-rights-reserved", "unknown", ""]

public struct CorpusItem {
    public let id: Data
    public let author: String
    public let title: String
    public let tags: [String]
    public let license: String
    public let priceAtlas: Int
    public let region: String
    public let origin: String      // provenance class: "" / "atlas-captured" / "imported" / "published"
    public init(id: Data, author: String, title: String, tags: [String],
                license: String = "open", priceAtlas: Int = 0, region: String = "",
                origin: String = "") {
        self.id = id; self.author = author; self.title = title; self.tags = tags
        self.license = license; self.priceAtlas = priceAtlas; self.region = region
        self.origin = origin
    }
}

public struct LibrarianHit: Identifiable {
    public let item: Data
    public let author: String
    public let title: String
    public let license: String
    public let priceAtlas: Int
    public let licensed: Bool      // holder may use/quote verbatim (open, or already bought)
    public let score: Int
    public let url: String         // link to the source (empty for local vault items)
    public let snippet: String     // a short info excerpt (empty for local vault items)
    public init(item: Data, author: String, title: String, license: String,
                priceAtlas: Int, licensed: Bool, score: Int,
                url: String = "", snippet: String = "") {
        self.item = item; self.author = author; self.title = title; self.license = license
        self.priceAtlas = priceAtlas; self.licensed = licensed; self.score = score
        self.url = url; self.snippet = snippet
    }
    public var id: Data { item }
    /// Surfaced but not yet usable → show a buy pointer.
    public var purchasable: Bool { !licensed && priceAtlas > 0 }
}

public enum Librarian {
    /// The fail-safe default license (see Library.swift / license-by-default).
    public static let allRightsReserved = "all-rights-reserved"

    /// A work is OPEN (free to use, still cited) if its license is copyleft/CC/open OR it carries
    /// no price. Everything else is a paid content license — usable only once bought. EXCEPT: an
    /// explicitly reserved/unknown license is never auto-open, even at price 0 — the fail-safe, so
    /// a missing license reads as "ask/buy", never "free".
    public static func isOpen(_ license: String, _ price: Int) -> Bool {
        let lic = license.trimmingCharacters(in: .whitespaces).lowercased()
        if reservedLicenses.contains(lic) { return false }
        return price <= 0 || openLicenses.contains(lic)
    }

    /// Lowercased word set — mirrors the Python/marketplace tokenizer.
    static func tokens(_ text: String) -> Set<String> {
        let cleaned = String(text.lowercased().map { $0.isLetter || $0.isNumber ? $0 : " " })
        return Set(cleaned.split(separator: " ").map(String.init).filter { !$0.isEmpty })
    }

    /// Rank corpus items by relevance to `query` (token overlap on title + tags), region-scoped if
    /// asked, and mark each licensed (open, or the holder bought it). Only genuine matches returned
    /// (pull, not push). Highest relevance first.
    public static func retrieve(_ query: String, _ corpus: [CorpusItem],
                                licensedIds: Set<Data> = [], region: String? = nil,
                                topK: Int = 10) -> [LibrarianHit] {
        let q = tokens(query)
        var hits: [LibrarianHit] = []
        for it in corpus {
            if let r = region, !it.region.isEmpty, it.region != r { continue }
            let itemTokens = tokens(it.title).union(it.tags.map { $0.lowercased() })
            let overlap = q.intersection(itemTokens).count
            if overlap == 0 { continue }
            let licensed = isOpen(it.license, it.priceAtlas) || licensedIds.contains(it.id)
            hits.append(LibrarianHit(item: it.id, author: it.author, title: it.title,
                                     license: it.license, priceAtlas: it.priceAtlas,
                                     licensed: licensed, score: overlap))
        }
        // relevance first, then already-licensed ahead of buy-to-unlock, then cheaper first
        hits.sort { a, b in
            if a.score != b.score { return a.score > b.score }
            if a.licensed != b.licensed { return a.licensed }
            return a.priceAtlas < b.priceAtlas
        }
        return Array(hits.prefix(topK))
    }
}
