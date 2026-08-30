import Foundation

/// Open-web + ethical-library retrieval TOOL — the DETERMINISTIC search layer that grounds the
/// generative AI. NOT a browser (no web rendering) and NO third-party VENDOR search surface:
/// scoped queries hit OPEN, non-vendor sources and return CITED results (title + snippet + link)
/// per the web-as-a-cited-tool seam. Every hit is the OPEN lane (free to use, still attributed).
///
/// Now: Wikipedia (Wikimedia, CC-BY-SA) + OpenAlex (the open non-profit scholarly index). NEXT
/// (general open-web, still no vendor): a SELF-HOSTED SearXNG on the node/VM. Gutenberg
/// (public domain) + Common Corpus (Pleias) slot in behind the same interface; the server-commons
/// ingests them into the shared register.
public enum WebLibrary {

    /// Your NODE's SearXNG base URL (e.g. "http://100.x.y.z:8888") — the live wider-web search
    /// tool, self-hosted, no vendor surface. nil = source off. Set once at app launch (before
    /// concurrent searches), hence nonisolated(unsafe).
    nonisolated(unsafe) public static var nodeSearchBase: String?

    /// Live wider-web results via the node's SearXNG (open metasearch you run yourself).
    static func nodeWeb(_ query: String, limit: Int) async -> [LibrarianHit] {
        guard let base = nodeSearchBase, !base.isEmpty,
              let q = query.trimmingCharacters(in: .whitespacesAndNewlines)
                .addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed), !q.isEmpty,
              let url = URL(string: "\(base)/search?q=\(q)&format=json")
        else { return [] }
        guard let (data, resp) = try? await URLSession.shared.data(from: url),
              (resp as? HTTPURLResponse)?.statusCode == 200,
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let results = json["results"] as? [[String: Any]]
        else { return [] }
        return results.prefix(limit).compactMap { r in
            guard let title = r["title"] as? String, let link = r["url"] as? String else { return nil }
            let snippet = (r["content"] as? String) ?? ""
            return LibrarianHit(item: Data("web:\(link)".utf8),
                                author: URL(string: link)?.host ?? "web", title: title,
                                license: "open", priceAtlas: 0, licensed: true, score: 1,
                                url: link, snippet: String(snippet.prefix(300)))
        }
    }

    /// Search the open library for `query`. Every result is a cited, open-lane `LibrarianHit`
    /// carrying a snippet + link. Sources run concurrently: encyclopedic (Wikipedia), scholarly
    /// (OpenAlex), and real-world PLACES (OpenStreetMap — business phone/website/address).
    public static func search(_ query: String, limit: Int = 5) async -> [LibrarianHit] {
        async let wiki = wikipedia(query, limit: limit)
        async let scholar = openAlex(query, limit: max(2, limit / 2))
        async let osm = places(query, limit: max(2, limit / 2))
        async let live = nodeWeb(query, limit: limit)          // node SearXNG (when configured)
        return (await live) + (await osm) + (await wiki) + (await scholar)
    }

    // MARK: Wikipedia (Wikimedia, CC-BY-SA)

    static func wikipedia(_ query: String, limit: Int) async -> [LibrarianHit] {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              let q = trimmed.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed),
              let url = URL(string: "https://en.wikipedia.org/w/api.php?action=query&list=search"
                            + "&srsearch=\(q)&srlimit=\(limit)&srprop=snippet&format=json")
        else { return [] }
        guard let (data, resp) = try? await URLSession.shared.data(from: url),
              (resp as? HTTPURLResponse)?.statusCode == 200,
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let queryObj = json["query"] as? [String: Any],
              let results = queryObj["search"] as? [[String: Any]]
        else { return [] }
        return results.compactMap { r in
            guard let title = r["title"] as? String else { return nil }
            let snippet = stripHTML((r["snippet"] as? String) ?? "")
            let page = title.replacingOccurrences(of: " ", with: "_")
                .addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? title
            return LibrarianHit(item: Data("wikipedia:\(title)".utf8),
                                author: "Wikipedia (CC-BY-SA)", title: title,
                                license: "cc-by-sa", priceAtlas: 0, licensed: true, score: 1,
                                url: "https://en.wikipedia.org/wiki/\(page)", snippet: snippet)
        }
    }

    // MARK: OpenStreetMap places (community open data, ODbL) — real-world lookups
    // (a business's phone/website/address), the non-vendor answer to "what's the
    // number of X mall". Coverage is what the community has mapped: phone/website
    // come from OSM contact tags when present.

    static func places(_ query: String, limit: Int) async -> [LibrarianHit] {
        // Nominatim matches PLACE NAMES, not sentences: try the raw text, then the part after
        // "of"/"for"/"to" ("phone number of milton mall" -> "milton mall").
        var candidates = [query.trimmingCharacters(in: .whitespacesAndNewlines)]
        let lower = candidates[0].lowercased()
        for sep in [" of ", " for ", " to "] {
            if let r = lower.range(of: sep, options: .backwards) {
                candidates.append(String(candidates[0][r.upperBound...])
                    .trimmingCharacters(in: CharacterSet(charactersIn: " ?.!,")))
            }
        }
        for cand in candidates where !cand.isEmpty {
            let hits = await placesLookup(cand, limit: limit)
            if !hits.isEmpty { return hits }
        }
        return []
    }

    private static func placesLookup(_ name: String, limit: Int) async -> [LibrarianHit] {
        guard let q = name.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed),
              let url = URL(string: "https://nominatim.openstreetmap.org/search?q=\(q)"
                            + "&format=jsonv2&limit=\(limit)&extratags=1&addressdetails=1")
        else { return [] }
        var req = URLRequest(url: url)
        req.setValue("AtlasPoC/1.0 (open librarian)", forHTTPHeaderField: "User-Agent")  // Nominatim policy
        guard let (data, resp) = try? await URLSession.shared.data(for: req),
              (resp as? HTTPURLResponse)?.statusCode == 200,
              let results = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]]
        else { return [] }
        return results.compactMap { r in
            guard let name = r["display_name"] as? String else { return nil }
            let title = (r["name"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? name
            let extra = (r["extratags"] as? [String: String]) ?? [:]
            var facts: [String] = []
            if let phone = extra["phone"] ?? extra["contact:phone"] { facts.append("phone: \(phone)") }
            if let site = extra["website"] ?? extra["contact:website"] { facts.append(site) }
            if let hours = extra["opening_hours"] { facts.append("hours: \(hours)") }
            facts.append(name)                                        // the address line
            let osmType = (r["osm_type"] as? String) ?? "node"
            let osmId = "\(r["osm_id"] ?? "")"
            return LibrarianHit(item: Data("osm:\(osmType)/\(osmId)".utf8),
                                author: "OpenStreetMap (ODbL)", title: title,
                                license: "open", priceAtlas: 0, licensed: true, score: 1,
                                url: "https://www.openstreetmap.org/\(osmType)/\(osmId)",
                                snippet: facts.joined(separator: " · "))
        }
    }

    // MARK: OpenAlex (open non-profit scholarly index)

    static func openAlex(_ query: String, limit: Int) async -> [LibrarianHit] {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              let q = trimmed.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed),
              let url = URL(string: "https://api.openalex.org/works?search=\(q)&per_page=\(limit)")
        else { return [] }
        guard let (data, resp) = try? await URLSession.shared.data(from: url),
              (resp as? HTTPURLResponse)?.statusCode == 200,
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let results = json["results"] as? [[String: Any]]
        else { return [] }
        return results.compactMap { w in
            guard let title = w["display_name"] as? String, !title.isEmpty else { return nil }
            let year = (w["publication_year"] as? Int).map { " (\($0))" } ?? ""
            var author = "OpenAlex (open academic)"
            if let auths = w["authorships"] as? [[String: Any]],
               let first = auths.first?["author"] as? [String: Any],
               let name = first["display_name"] as? String {
                author = name + (auths.count > 1 ? " et al." : "") + " · OpenAlex"
            }
            let link = (w["doi"] as? String) ?? (w["id"] as? String) ?? ""
            let abstract = reconstructAbstract(w["abstract_inverted_index"])
            return LibrarianHit(item: Data("openalex:\(title)".utf8),
                                author: author, title: title + year,
                                license: "open", priceAtlas: 0, licensed: true, score: 1,
                                url: link, snippet: abstract)
        }
    }

    /// OpenAlex ships abstracts as an inverted index (word -> positions); rebuild the text.
    static func reconstructAbstract(_ raw: Any?) -> String {
        guard let inv = raw as? [String: [Int]] else { return "" }
        var placed: [(Int, String)] = []
        for (word, positions) in inv { for p in positions { placed.append((p, word)) } }
        placed.sort { $0.0 < $1.0 }
        return placed.map { $0.1 }.joined(separator: " ")
    }

    // MARK: helpers

    static func stripHTML(_ s: String) -> String {
        var out = ""
        var inTag = false
        for ch in s {
            if ch == "<" { inTag = true } else if ch == ">" { inTag = false } else if !inTag { out.append(ch) }
        }
        return out.replacingOccurrences(of: "&quot;", with: "\"")
            .replacingOccurrences(of: "&amp;", with: "&")
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
