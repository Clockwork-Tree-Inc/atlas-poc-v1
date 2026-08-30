import XCTest
@testable import AtlasCore

/// Cross-language interop: the Swift/blst serializations of G1, G2, scalars, and hash-to-scalar are
/// byte-identical to the Python backend (py_ecc). This makes a backend-issued CREDENTIAL and PUBLIC KEY
/// portable to the phone — the holder loads and presents it on-device. (GT/proof cross-verify is a
/// separate library-representation matter — py_ecc uses a direct field, blst a tower.)
final class BLSInteropTests: XCTestCase {
    private func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }

    func testG1SerializationMatchesPython() {
        XCTAssertEqual(hex(G1.generator.mul(Fr(fromUInt64: 5)).serialize()),
            "10e7791fb972fe014159aa33a98622da3cdc98ff707965e536d8636b5fcc5ac7a91a8c46e59a00dca575af0f18fb13dc16ba437edcc6551e30c10512367494bfb6b01cc6681e8a4c3cd2501832ab5c4abc40b4578b85cbaffbf0bcd70d67c6e2")
    }

    func testG2SerializationMatchesPython() {
        XCTAssertEqual(hex(G2.generator.mul(Fr(fromUInt64: 5)).serialize()),
            "0411a5de6730ffece671a9f21d65028cc0f1102378de124562cb1ff49db6f004fcd14d683024b0548eff3d1468df268800fb837804dba8213329db46608b6c121d973363c1234a86dd183baff112709cf97096c5e9a1a770ee9d7dc641a894d619b5e8f5d4a72f2b75811ac084a7f814317360bac52f6aab15eed416b4ef9938e0bdc4865cc2c4d0fd947e7c6925fd14093567b4228be17ee62d11a254edd041ee4b953bffb8b8c7f925bd6662b4298bac2822b446f5b5de3b893e1be5aa4986")
    }

    func testMsgScalarMatchesPython() {
        XCTAssertEqual(hex(Fr.msg("work:BSc").bytesBE()),
                       "6cca0dcc54dcba7d5ddf9b4ad736c72e61df7a4ab438538665e1e8bedef0e417")
    }

    func testHashToScalarMatchesPython() {
        XCTAssertEqual(hex(Fr.hash([Data("a".utf8), Data("bc".utf8)]).bytesBE()),
                       "3837e9de8b0baba727444dd943c365179346a91e4a678ab9d935cfaf76da4347")
    }

    func testG2RoundTrip() {
        let p = G2.generator.mul(Fr.random())
        XCTAssertEqual(G2.deserialize(p.serialize())?.serialize(), p.serialize())
    }
}
