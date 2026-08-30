import XCTest
@testable import AtlasCore

final class BLS12381Tests: XCTestCase {
    func testVendoredBlstLinksAndPairs() {
        // e(G1, G2) != 1 — proves the vendored blst compiles, links, and runs on this platform.
        XCTAssertTrue(BLS12381.pairingSelfCheck())
    }
}
