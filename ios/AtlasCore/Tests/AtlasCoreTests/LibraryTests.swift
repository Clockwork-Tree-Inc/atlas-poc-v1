import XCTest
@testable import AtlasCore

/// Federated library registry (Swift), parity with `backend/atlas/ai/library.py` /
/// `backend/tests/test_library.py`: plug in many LibrarySources, rank globally, tag provenance, and
/// enforce license-by-default (no/unknown license -> all-rights-reserved, never accidentally free).
final class LibraryTests: XCTestCase {
    private func d(_ s: String) -> Data { Data(s.utf8) }

    private func vault() -> InMemorySource {
        InMemorySource(name: "vault", items: [
            CorpusItem(id: d("v1"), author: "me", title: "My tide notes", tags: ["tide", "notes"],
                       license: "cc-by", priceAtlas: 0),
        ])
    }
    private func auracles() -> InMemorySource {
        InMemorySource(name: "auracles", items: [
            CorpusItem(id: d("a1"), author: "imogen", title: "Tide song", tags: ["tide", "music"],
                       license: "content:quote", priceAtlas: 40),
            CorpusItem(id: d("a2"), author: "anon", title: "Unmarked tide loop", tags: ["tide", "loop"],
                       license: "", priceAtlas: 0),                       // NO LICENSE -> fail-safe
        ])
    }

    func testNormalizeLicenseIsFailSafe() {
        XCTAssertEqual(normalizeLicense(CorpusItem(id: d("x"), author: "a", title: "t", tags: [], license: "")).license,
                       Librarian.allRightsReserved)
        XCTAssertEqual(normalizeLicense(CorpusItem(id: d("x"), author: "a", title: "t", tags: [], license: "unknown")).license,
                       Librarian.allRightsReserved)
        XCTAssertEqual(normalizeLicense(CorpusItem(id: d("x"), author: "a", title: "t", tags: [], license: "CC-BY")).license,
                       "cc-by")
    }

    func testReservedIsNotOpenEvenAtPriceZero() {
        XCTAssertFalse(Librarian.isOpen(Librarian.allRightsReserved, 0))   // the whole point of #26
        XCTAssertFalse(Librarian.isOpen("", 0))
        XCTAssertTrue(Librarian.isOpen("cc-by", 0))
        XCTAssertTrue(Librarian.isOpen("content:read", 0))                 // price 0 -> open (unchanged)
    }

    func testRegistryAggregatesWithProvenance() {
        let reg = LibraryRegistry()
        reg.register(vault())
        reg.register(auracles())
        XCTAssertEqual(reg.sources, ["vault", "auracles"])
        let byID = Dictionary(uniqueKeysWithValues: reg.search("tide").map { ($0.hit.item, $0) })
        XCTAssertEqual(Set(byID.keys), [d("v1"), d("a1"), d("a2")])
        XCTAssertEqual(byID[d("v1")]?.source, "vault")
        XCTAssertEqual(byID[d("a1")]?.source, "auracles")
    }

    func testLicenseByDefaultMarksUnlicensedNotUsable() {
        let reg = LibraryRegistry()
        reg.register(auracles())
        let hits = Dictionary(uniqueKeysWithValues: reg.search("tide").map { ($0.hit.item, $0.hit) })
        XCTAssertEqual(hits[d("a2")]?.license, Librarian.allRightsReserved)
        XCTAssertEqual(hits[d("a2")]?.licensed, false)
        XCTAssertEqual(hits[d("a2")]?.purchasable, false)                  // reserved + price 0 -> "ask"
        XCTAssertEqual(hits[d("a1")]?.licensed, false)
        XCTAssertEqual(hits[d("a1")]?.purchasable, true)                   // paid -> buy pointer
    }

    func testFirstSourceWinsOnDuplicateID() {
        let s1 = InMemorySource(name: "first", items: [
            CorpusItem(id: d("dup"), author: "x", title: "tide A", tags: ["tide"], license: "cc-by")])
        let s2 = InMemorySource(name: "second", items: [
            CorpusItem(id: d("dup"), author: "y", title: "tide B", tags: ["tide"], license: "content:quote", priceAtlas: 99)])
        let reg = LibraryRegistry()
        reg.register(s1)
        reg.register(s2)
        let (corpus, origin) = reg.gather("tide")
        XCTAssertEqual(origin[d("dup")], "first")
        XCTAssertEqual(corpus.first(where: { $0.id == d("dup") })?.license, "cc-by")
    }
}
