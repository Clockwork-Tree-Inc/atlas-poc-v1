import XCTest
@testable import AtlasCore

/// The in-app SystemCheck engine must reproduce the parity result on-Mac too:
/// every category present and every vector matching. This guards the public
/// SystemCheck API the app calls (the health monitor) against regressions.
final class SystemCheckTests: XCTestCase {
    func testSystemCheckAllCategoriesPass() {
        let results = SystemCheck.run()
        XCTAssertFalse(results.isEmpty, "SystemCheck produced no results (vectors not bundled?)")
        for r in results {
            XCTAssertTrue(r.ok, "SystemCheck category '\(r.name)' failed: \(r.detail)")
        }
        // sanity: the load-bearing categories are actually present
        let names = Set(results.map(\.name))
        for expected in ["SHA3-256", "HKDF", "Forward-secret ratchet", "Session key (decoupled)", "X-Wing KEM combiner"] {
            XCTAssertTrue(names.contains(expected), "missing category \(expected)")
        }
    }
}
