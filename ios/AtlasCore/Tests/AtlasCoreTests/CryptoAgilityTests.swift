import XCTest
@testable import AtlasCore

/// Native-logic parity for the crypto-agility seam (TRUST_LAYER.md #10) — kept in lockstep with
/// backend/tests/test_agility.py.
final class CryptoAgilityTests: XCTestCase {
    typealias Family = CryptoAgility.SchemeFamily
    typealias Suite = CryptoAgility.CryptoSuite
    typealias SchemeId = CryptoAgility.SchemeId

    private func registry() -> CryptoAgility.SchemeRegistry {
        let r = CryptoAgility.SchemeRegistry()
        r.register(SchemeId(family: .kem, name: "ml-kem-768+x25519", pq: true), impl: 0, isDefault: true)
        r.register(SchemeId(family: .signature, name: "ml-dsa-65+ed25519", pq: true), impl: 0, isDefault: true)
        r.register(SchemeId(family: .signature, name: "sphincs+", pq: true), impl: 0)
        r.register(SchemeId(family: .credential, name: "bbs+", pq: false), impl: 0, isDefault: true)
        r.register(SchemeId(family: .credential, name: "ps", pq: false), impl: 0)
        return r
    }

    func testRegistryDefaultAvailableUnknown() throws {
        let r = registry()
        XCTAssertEqual(try r.defaultName(.kem), "ml-kem-768+x25519")
        XCTAssertEqual(Set(r.available(.credential).map { $0.name }), ["bbs+", "ps"])
        XCTAssertThrowsError(try r.schemeId(.credential, "nope")) {
            XCTAssertEqual($0 as? CryptoAgility.AgilityError, .unknownScheme)
        }
    }

    func testSwapByName() throws {
        let r = registry()
        XCTAssertEqual(try r.defaultName(.credential), "bbs+")
        r.register(SchemeId(family: .credential, name: "ps", pq: false), impl: 0, isDefault: true)
        XCTAssertEqual(try r.defaultName(.credential), "ps")
    }

    func testSuiteIdDeterministicAndSensitive() {
        let s = Suite(version: 1, kem: "ml-kem-768+x25519", signature: "ml-dsa-65+ed25519", credential: "bbs+")
        XCTAssertEqual(s.suiteId(), Suite(version: 1, kem: "ml-kem-768+x25519",
                                          signature: "ml-dsa-65+ed25519", credential: "bbs+").suiteId())
        XCTAssertNotEqual(s.suiteId(), Suite(version: 2, kem: "ml-kem-768+x25519",
                                             signature: "ml-dsa-65+ed25519", credential: "bbs+").suiteId())
        // length-prefix framing: a boundary shift must not collide
        XCTAssertNotEqual(Suite(version: 1, kem: "ab", signature: "c", credential: "d").suiteId(),
                          Suite(version: 1, kem: "a", signature: "bc", credential: "d").suiteId())
    }

    func testNegotiate() throws {
        let strong = Suite(version: 2, kem: "ml-kem-768+x25519", signature: "ml-dsa-65+ed25519", credential: "ps")
        let weak = Suite(version: 1, kem: "ml-kem-768+x25519", signature: "ml-dsa-65+ed25519", credential: "bbs+")
        XCTAssertEqual(try CryptoAgility.negotiate(preference: [strong, weak], remoteIDs: [weak.suiteId()]), weak)
        XCTAssertEqual(try CryptoAgility.negotiate(preference: [strong, weak],
                                                   remoteIDs: [strong.suiteId(), weak.suiteId()]), strong)
        XCTAssertThrowsError(try CryptoAgility.negotiate(preference: [strong], remoteIDs: [Data("x".utf8)])) {
            XCTAssertEqual($0 as? CryptoAgility.AgilityError, .noCommonSuite)
        }
    }

    func testNegotiateStrengthFloor() throws {
        let strong = Suite(version: 2, kem: "ml-kem-768+x25519", signature: "ml-dsa-65+ed25519", credential: "ps")
        let weak = Suite(version: 1, kem: "ml-kem-768+x25519", signature: "ml-dsa-65+ed25519", credential: "bbs+")
        let floor: (Suite) -> Bool = { $0.version >= 2 }        // a simple strength floor
        // only the weak suite overlaps, but it's below the floor -> fail closed
        XCTAssertThrowsError(try CryptoAgility.negotiate(preference: [weak], remoteIDs: [weak.suiteId()], acceptable: floor))
        // a floor-meeting suite is chosen when mutually supported
        XCTAssertEqual(try CryptoAgility.negotiate(preference: [strong, weak],
                       remoteIDs: [strong.suiteId(), weak.suiteId()], acceptable: floor), strong)
    }
}
