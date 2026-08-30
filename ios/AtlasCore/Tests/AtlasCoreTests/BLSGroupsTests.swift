import XCTest
@testable import AtlasCore

final class BLSGroupsTests: XCTestCase {
    func testScalarInverseAndArithmetic() {
        let a = Fr.random()
        XCTAssertEqual(a * a.inverse, Fr.one)
        XCTAssertEqual(a + a.negated, Fr.zero)
        XCTAssertEqual(Fr(fromUInt64: 3) * Fr(fromUInt64: 4), Fr(fromUInt64: 12))
    }

    func testG1SerializeRoundTrip() {
        let p = G1.generator.mul(Fr.random())
        let back = G1.deserialize(p.serialize())
        XCTAssertNotNil(back)
        XCTAssertEqual(p, back!)
        XCTAssertTrue(p.isValid())
    }

    func testBilinearity() {
        // e(aG1, bG2) == e(G1,G2)^(ab)
        let a = Fr.random(), b = Fr.random()
        let lhs = GT.pairing(G1.generator.mul(a), G2.generator.mul(b))
        let rhs = GT.pairing(G1.generator, G2.generator).pow(a * b)
        XCTAssertEqual(lhs, rhs)
    }

    func testGtPowMatchesPairingOfScaledPoint() {
        // e(G1,G2)^s == e(sG1, G2)
        let s = Fr.random()
        let viaPow = GT.pairing(G1.generator, G2.generator).pow(s)
        let viaPoint = GT.pairing(G1.generator.mul(s), G2.generator)
        XCTAssertEqual(viaPow, viaPoint)
    }

    func testGtInverse() {
        let g = GT.pairing(G1.generator.mul(Fr.random()), G2.generator)
        XCTAssertTrue((g * g.inverse).isOne())
    }
}
