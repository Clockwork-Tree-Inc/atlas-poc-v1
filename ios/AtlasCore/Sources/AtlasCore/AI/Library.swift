import Foundation

/// Federated library — a pluggable registry of LibrarySources feeding the librarian.
/// Swift parity with `backend/atlas/ai/library.py` (Python reference of record).
///
/// Every device is an author's shelf; outside libraries plug in as adapters — the on-device vault,
/// the public register, and external catalogs (a music-rights layer like auracles, a legal library,
/// a standards body). The registry queries them all, tags every result with WHICH source surfaced
/// it (provenance), and ranks globally through the librarian's `retrieve`.
///
/// Two guarantees on top of the librarian:
///   LICENSE-BY-DEFAULT (fail-safe): an item arriving without an explicit license is stamped
///   all-rights-reserved before retrieval — never open by omission, not usable even at price 0.
///   PROVENANCE: each hit carries the name of the source that surfaced it.
///
/// Pull-only: sources are searched, never pushed. Adapters may push the query down or return
/// candidates; the registry license-normalizes + ranks centrally either way.

/// A pluggable library. `name` is the provenance tag attached to everything it surfaces; `search`
/// returns its authored/licensed candidate works (pull-only). External adapters implement the same.
public protocol LibrarySource {
    var name: String { get }
    func search(_ query: String, region: String?, topK: Int) -> [CorpusItem]
}

public extension LibrarySource {
    func search(_ query: String) -> [CorpusItem] { search(query, region: nil, topK: 20) }
}

/// A LibrarySource backed by a fixed list — the on-device vault shelf, or a stub for an external
/// adapter. Real adapters implement `LibrarySource` over their catalog.
public struct InMemorySource: LibrarySource {
    public let name: String
    public let items: [CorpusItem]
    public init(name: String, items: [CorpusItem]) { self.name = name; self.items = items }

    public func search(_ query: String, region: String?, topK: Int) -> [CorpusItem] {
        items      // pull-only; the registry ranks + license-normalizes centrally
    }
}

/// License-by-default: a blank/unknown license becomes all-rights-reserved (fail-safe restrictive);
/// an explicit license is lower-cased and kept.
public func normalizeLicense(_ item: CorpusItem) -> CorpusItem {
    let lic = item.license.trimmingCharacters(in: .whitespaces).lowercased()
    let normalized = (lic.isEmpty || lic == "unknown") ? Librarian.allRightsReserved : lic
    return CorpusItem(id: item.id, author: item.author, title: item.title, tags: item.tags,
                      license: normalized, priceAtlas: item.priceAtlas, region: item.region,
                      origin: item.origin)
}

/// A librarian hit plus the provenance of the source that surfaced it.
public struct SourcedHit {
    public let hit: LibrarianHit
    public let source: String
}

/// The set of plugged-in libraries. Query them all, license-normalize + dedup, rank globally.
public final class LibraryRegistry {
    private var registered: [LibrarySource] = []
    public init() {}

    public func register(_ source: LibrarySource) { registered.append(source) }

    public var sources: [String] { registered.map { $0.name } }

    /// Collect license-normalized candidates from every source into one corpus, remembering which
    /// source surfaced each id. First source to surface an id wins (stable, order-of-registration).
    public func gather(_ query: String, region: String? = nil, topK: Int = 20)
        -> (corpus: [CorpusItem], origin: [Data: String]) {
        var merged: [Data: CorpusItem] = [:]
        var order: [Data] = []
        var origin: [Data: String] = [:]
        for s in registered {
            for raw in s.search(query, region: region, topK: topK) {
                let item = normalizeLicense(raw)
                if merged[item.id] == nil {
                    merged[item.id] = item
                    order.append(item.id)
                    origin[item.id] = s.name
                }
            }
        }
        return (order.map { merged[$0]! }, origin)   // preserve first-seen order
    }

    /// Ranked hits across all plugged-in libraries, each tagged with its source.
    public func search(_ query: String, region: String? = nil, topK: Int = 10,
                       licensedIds: Set<Data> = []) -> [SourcedHit] {
        let (corpus, origin) = gather(query, region: region, topK: topK)
        return Librarian.retrieve(query, corpus, licensedIds: licensedIds, region: region, topK: topK)
            .map { SourcedHit(hit: $0, source: origin[$0.item] ?? "?") }
    }
}
