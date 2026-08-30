import XCTest
@testable import AtlasCore

/// YubiKey Bio + USB recovery hardware factors. Mirrors
/// `backend/tests/test_hardware_key.py` and `test_usb_recovery.py`.
final class HardwareFactorTests: XCTestCase {

    private func req(_ action: String = "recover", _ ctx: String = "ctx",
                     _ chal: String = "nonce-1") -> HighStakesRequest {
        HighStakesRequest(action: action, context: Data(ctx.utf8), challenge: Data(chal.utf8))
    }

    // -- YubiKey Bio ----------------------------------------------------------

    func testHighStakesMessageParity() {
        // H(atlas/high-stakes, "recover", "ctx", "nonce-1") — vector from the Python reference
        XCTAssertEqual(req().message().base64EncodedString(), "huoYWdon3GuOJQiC3GulEA4vSarE1HDo+v3WCb73SdI=")
    }

    func testAuthorizedWithFingerprintVerifies() throws {
        let key = YubiKeyBio()
        let r = req()
        let sig = try key.authorize(r, fingerprintMatched: true)
        XCTAssertTrue(verifyHighStakes(key.publicKey, r, sig))
    }

    func testNoFingerprintRefusesToSign() {
        XCTAssertThrowsError(try YubiKeyBio().authorize(req(), fingerprintMatched: false)) { err in
            guard case HardwareKeyError.fingerprintRequired = err else { return XCTFail("expected fingerprintRequired") }
        }
    }

    func testSignatureDoesNotVerifyForADifferentAction() throws {
        let key = YubiKeyBio()
        let sig = try key.authorize(req("recover", "ctx", "n1"), fingerprintMatched: true)
        XCTAssertFalse(verifyHighStakes(key.publicKey, req("transfer", "ctx", "n1"), sig))
        XCTAssertFalse(verifyHighStakes(key.publicKey, req("recover", "ctx", "n2"), sig))
        XCTAssertFalse(verifyHighStakes(key.publicKey, req("recover", "other", "n1"), sig))
    }

    func testWrongKeyDoesNotVerify() throws {
        let a = YubiKeyBio(), b = YubiKeyBio()
        let r = req()
        let sig = try a.authorize(r, fingerprintMatched: true)
        XCTAssertFalse(verifyHighStakes(b.publicKey, r, sig))
    }

    func testShareReleaseIsFingerprintGated() throws {
        let key = YubiKeyBio()
        let share = Shamir.split(Data(repeating: 0x53, count: 32), n: 3, k: 2)[0]
        key.holdRecoveryShare(share)
        XCTAssertThrowsError(try key.releaseRecoveryShare(fingerprintMatched: false))
        XCTAssertEqual(try key.releaseRecoveryShare(fingerprintMatched: true).encode(), share.encode())
    }

    // -- USB recovery ---------------------------------------------------------

    func testUSBWriteReadRoundtripThroughDriveBytes() throws {
        let share = Shamir.split(Data(repeating: 0x53, count: 32), n: 3, k: 2)[0]
        let recovery = HybridKEM.generateKeypair()
        let blob = try writeShareToUSB(share, recoveryPub: recovery.publicKey)
        let onDisk = try USBRecoveryBlob.fromBytes(blob.toBytes())   // survives the raw drive bytes
        XCTAssertEqual(try readShareFromUSB(onDisk, recoveryKP: recovery).encode(), share.encode())
    }

    func testLostDriveOpaqueWithoutRecoveryKey() throws {
        let share = Shamir.split(Data(repeating: 0x53, count: 32), n: 3, k: 2)[0]
        let recovery = HybridKEM.generateKeypair()
        let blob = try writeShareToUSB(share, recoveryPub: recovery.publicKey)
        // no plaintext share on the drive...
        XCTAssertNil(blob.toBytes().range(of: share.encode()))
        // ...and a different key can't read it (fail-closed)
        XCTAssertThrowsError(try readShareFromUSB(blob, recoveryKP: HybridKEM.generateKeypair()))
    }
}
