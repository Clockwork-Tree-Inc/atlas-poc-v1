import XCTest
@testable import AtlasCore

/// Real-ID verifier seam (Swift), parity with `backend/atlas/realid/verifier.py` document core.
final class VerifierTests: XCTestCase {
    private func kp() throws -> HybridSign.Keypair { try HybridSign.keypair(fromSeed: Primitives.randomBytes(32)) }
    private func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    func testNullifierAndSodParityKAT() {
        XCTAssertEqual(hex(RealIDVerifier.documentNullifier(Data("kat-doc".utf8))),
                       "11f07145a0f49f76a6871f77227477295391c494f6392374fe17e5870ced9d15")
        XCTAssertEqual(hex(RealIDVerifier.sod(Data("kat-doc".utf8))),
                       "ff9d6a3ec111bf0bf7b59194059394e5e3f615998111dfe604c58cd74ee9757d")
    }

    func testChipVerifiesAndCertifiesHighConfidence() throws {
        let csca = try kp()
        let att = try RealIDVerifier.mintChipAttestation(csca: csca, dsc: try kp(), docUnique: Data("passport:CAN:AA1234".utf8))
        XCTAssertTrue(RealIDVerifier.verifyChip(att, cscaPub: csca.publicKey))
        let v = RealIDVerifier.Verifier(cscaPub: csca.publicKey)
        let r = try v.certify(systemIDHandle: Data("sid".utf8), att, livePresent: true)
        XCTAssertTrue(r.cryptographic)
    }

    func testBadChainRejected() throws {
        let csca = try kp()
        let att = try RealIDVerifier.mintChipAttestation(csca: try kp(), dsc: try kp(), docUnique: Data("p".utf8))  // wrong CSCA
        XCTAssertFalse(RealIDVerifier.verifyChip(att, cscaPub: csca.publicKey))
        let v = RealIDVerifier.Verifier(cscaPub: csca.publicKey)
        XCTAssertThrowsError(try v.certify(systemIDHandle: Data("sid".utf8), att, livePresent: true))
    }

    func testLivenessRequired() throws {
        let csca = try kp()
        let att = try RealIDVerifier.mintChipAttestation(csca: csca, dsc: try kp(), docUnique: Data("p".utf8))
        let v = RealIDVerifier.Verifier(cscaPub: csca.publicKey)
        XCTAssertThrowsError(try v.certify(systemIDHandle: Data("sid".utf8), att, livePresent: false))
    }

    func testVendorPathIsLabeledLowerConfidence() throws {
        let v = RealIDVerifier.Verifier(cscaPub: try kp().publicKey)
        let ok = RealIDVerifier.DocumentAttestation(path: .vendor, docUnique: Data("dl:onfido".utf8), vendorOk: true)
        XCTAssertFalse(try v.certify(systemIDHandle: Data("sid".utf8), ok, livePresent: true).cryptographic)   // labeled
        let bad = RealIDVerifier.DocumentAttestation(path: .vendor, docUnique: Data("dl:no".utf8), vendorOk: false)
        XCTAssertThrowsError(try v.certify(systemIDHandle: Data("sid".utf8), bad, livePresent: true))
    }

    func testDocumentReuseBlocked() throws {
        let csca = try kp()
        let att = try RealIDVerifier.mintChipAttestation(csca: csca, dsc: try kp(), docUnique: Data("passport:ZZ9999".utf8))
        let v = RealIDVerifier.Verifier(cscaPub: csca.publicKey)
        _ = try v.certify(systemIDHandle: Data("sid-1".utf8), att, livePresent: true)
        _ = try v.certify(systemIDHandle: Data("sid-1".utf8), att, livePresent: true)   // same person re-certifies -> ok
        XCTAssertThrowsError(try v.certify(systemIDHandle: Data("sid-2".utf8), att, livePresent: true))  // different System-ID -> reuse blocked
    }
}
