import XCTest
@testable import AtlasCore

final class SessionRecorderTests: XCTestCase {
    private func rec() -> SessionRecorder { SessionRecorder(sessionID: Data("sess-1".utf8)) }

    func testChainVerifiesAndHeadAdvances() {
        let r = rec()
        let h0 = r.headHash
        r.record(subsystem: "crypto", event: "sha3", ok: true, detail: "8/8", ts: 1000)
        let h1 = r.headHash
        r.record(subsystem: "gate", event: "unwrap", ok: true, detail: "ok", ts: 1001)
        let h2 = r.headHash
        XCTAssertEqual(r.entries.count, 2)
        XCTAssertTrue(r.verifyChain())
        XCTAssertTrue(r.allPassed)
        XCTAssertNotEqual(h0, h1)
        XCTAssertNotEqual(h1, h2)   // each record advances the head
    }

    func testAllPassedReflectsFailuresButChainStaysValid() {
        let r = rec()
        r.record(subsystem: "crypto", event: "sha3", ok: true, ts: 1)
        r.record(subsystem: "crypto", event: "hkdf", ok: false, detail: "3/4", ts: 2)
        XCTAssertFalse(r.allPassed)         // a recorded failure is honest data
        XCTAssertTrue(r.verifyChain())      // the chain over it is still valid
    }

    func testDeterministicAndSensitive() {
        let a = rec(); let b = rec()
        a.record(subsystem: "x", event: "e", ok: true, ts: 5)
        b.record(subsystem: "x", event: "e", ok: true, ts: 5)
        XCTAssertEqual(a.headHash, b.headHash)     // same inputs -> same head
        let c = rec()
        c.record(subsystem: "x", event: "e2", ok: true, ts: 5)
        XCTAssertNotEqual(a.headHash, c.headHash)  // a single field change -> different head
    }

    func testExportProofShape() throws {
        let r = rec()
        r.record(subsystem: "crypto", event: "sha3", ok: true, ts: 1)
        let data = r.exportProof(signatureHex: "deadbeef", signerKeyIDHex: "cafe")
        let obj = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(obj["kind"] as? String, "atlas/session-proof/v1")
        XCTAssertEqual(obj["chain_valid"] as? Bool, true)
        XCTAssertEqual(obj["signature"] as? String, "deadbeef")
        XCTAssertEqual((obj["entries"] as? [[String: Any]])?.count, 1)
    }
}
