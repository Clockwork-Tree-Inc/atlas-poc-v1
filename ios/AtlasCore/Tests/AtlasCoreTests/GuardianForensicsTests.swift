import XCTest
@testable import AtlasCore

final class GuardianForensicsTests: XCTestCase {

    func testBothSharesCollectTheCapture() throws {
        let key = GuardianForensics.newForensicKey()
        let blob = try GuardianForensics.sealForensic(forensicKey: key,
                                                      data: Data("black-box".utf8))
        let grant = try GuardianForensics.setupGuardian(forensicKey: key)
        let recovered = try GuardianForensics.collectForensicKey(contactShare: grant.contactShare,
                                                                 ownerShare: grant.ownerShare)
        XCTAssertEqual(recovered, key)
        XCTAssertEqual(try GuardianForensics.openForensic(forensicKey: recovered, blob: blob),
                       Data("black-box".utf8))
    }

    func testContactShareAloneIsInert() throws {
        let grant = try GuardianForensics.setupGuardian(forensicKey: GuardianForensics.newForensicKey())
        XCTAssertThrowsError(try GuardianForensics.collectForensicKey(contactShare: grant.contactShare,
                                                                      ownerShare: grant.contactShare))
    }

    func testForeignOwnerShareCollectsNothing() throws {
        let keyA = GuardianForensics.newForensicKey()
        let blobA = try GuardianForensics.sealForensic(forensicKey: keyA, data: Data("A".utf8))
        let grantA = try GuardianForensics.setupGuardian(forensicKey: keyA)
        let grantB = try GuardianForensics.setupGuardian(forensicKey: GuardianForensics.newForensicKey())

        let wrong = try GuardianForensics.collectForensicKey(contactShare: grantA.contactShare,
                                                             ownerShare: grantB.ownerShare)
        XCTAssertNotEqual(wrong, keyA)
        XCTAssertThrowsError(try GuardianForensics.openForensic(forensicKey: wrong, blob: blobA))
    }

    func testForensicKeyMinimumLength() {
        XCTAssertThrowsError(try GuardianForensics.setupGuardian(forensicKey: Data("tooshort".utf8)))
    }

    func testSharesRoundtripAsBytes() throws {
        let key = GuardianForensics.newForensicKey()
        let grant = try GuardianForensics.setupGuardian(forensicKey: key)
        let c = Shamir.Share.decode(grant.contactShare.encode())
        let o = Shamir.Share.decode(grant.ownerShare.encode())
        XCTAssertEqual(try GuardianForensics.collectForensicKey(contactShare: c, ownerShare: o), key)
    }
}
