import XCTest
import CryptoKit
@testable import AtlasCore

/// Native-logic parity for the device-attestation contract (TRUST_LAYER.md #11) — kept in
/// lockstep with backend/tests/test_attestation.py.
final class TrustedDeviceTests: XCTestCase {
    typealias Cap = TrustedDevice.Capability
    typealias Tier = TrustedDevice.AssuranceTier

    private let device = Data("device-1".utf8)
    private let challenge = Data("fresh-challenge".utf8)

    private func attestor() -> (Curve25519.Signing.PrivateKey, Data) {
        let sk = Curve25519.Signing.PrivateKey()
        return (sk, sk.publicKey.rawRepresentation)
    }
    private func signed(_ sk: Curve25519.Signing.PrivateKey, _ caps: Cap...) -> [TrustedDevice.CapabilityClaim] {
        caps.map { TrustedDevice.CapabilityClaim(capability: $0,
            evidence: TrustedDevice.signCapability(sk, deviceID: device, capability: $0, challenge: challenge)) }
    }

    func testTierLadder() {
        XCTAssertEqual(TrustedDevice.assuranceTier([]), .none)
        XCTAssertEqual(TrustedDevice.assuranceTier([.liveness]), .presence)
        XCTAssertEqual(TrustedDevice.assuranceTier([.liveness, .highRateIMU]), .bound)
        XCTAssertEqual(TrustedDevice.assuranceTier([.liveness, .sameBody]), .bound)  // OR-binding
        XCTAssertEqual(TrustedDevice.assuranceTier([.liveness, .sameBody, .secureElement]), .attested)
        XCTAssertEqual(TrustedDevice.assuranceTier([.liveness, .highRateIMU, .secureElement, .identity]),
                       .identified)
    }

    func testFailClosed() {
        XCTAssertEqual(TrustedDevice.assuranceTier([.secureElement, .identity]), .none)
        XCTAssertEqual(TrustedDevice.assuranceTier([.liveness, .secureElement]), .presence)
        XCTAssertEqual(TrustedDevice.assuranceTier([.liveness, .highRateIMU, .identity]), .bound)
        XCTAssertEqual(TrustedDevice.assuranceTier([.liveness, .onBodyMotion]), .presence)
    }

    func testCapabilitiesProvenBySignatureNotAsserted() {
        let (sk, pub) = attestor()
        let claims = signed(sk, .liveness, .highRateIMU) + [
            TrustedDevice.CapabilityClaim(capability: .secureElement, evidence: Data()),          // dropped
            TrustedDevice.CapabilityClaim(capability: .identity, evidence: Data("junk".utf8)),    // forged -> dropped
        ]
        let proven = TrustedDevice.deriveCapabilities(claims, attestorPublic: pub, deviceID: device, challenge: challenge)
        XCTAssertTrue(proven.contains(.liveness) && proven.contains(.highRateIMU))
        XCTAssertFalse(proven.contains(.secureElement) || proven.contains(.identity))
        XCTAssertEqual(TrustedDevice.assuranceTier(proven), .bound)
    }

    func testForgedEvidenceFailsClosed() {
        let (_, pub) = attestor()
        let forged: [TrustedDevice.CapabilityClaim] = [.liveness, .highRateIMU, .secureElement, .identity]
            .map { TrustedDevice.CapabilityClaim(capability: $0, evidence: Data("x".utf8)) }
        let a = TrustedDevice.Attestation.fromClaims(deviceID: device, claims: forged, attestorPublic: pub, challenge: challenge)
        XCTAssertEqual(a.tier, .none)                    // was .identified before verification
    }

    func testWrongChallengeOrKeyRejected() {
        let (sk, pub) = attestor()
        let (_, otherPub) = attestor()
        let claims = signed(sk, .liveness, .sameBody, .secureElement)
        XCTAssertEqual(TrustedDevice.deriveCapabilities(claims, attestorPublic: pub, deviceID: device, challenge: Data("other".utf8)), [])
        XCTAssertEqual(TrustedDevice.deriveCapabilities(claims, attestorPublic: otherPub, deviceID: device, challenge: challenge), [])
    }

    func testAttestationMeetsAndDigest() {
        let (sk, pub) = attestor()
        let a = TrustedDevice.Attestation.fromClaims(deviceID: device,
            claims: signed(sk, .liveness, .sameBody, .secureElement), attestorPublic: pub, challenge: challenge)
        XCTAssertEqual(a.tier, .attested)
        XCTAssertTrue(a.meets(.presence) && a.meets(.attested))
        XCTAssertFalse(a.meets(.identified))
        XCTAssertEqual(a.digest(), a.digest())
    }

    func testCapabilityBitValues() {
        XCTAssertEqual([Cap.liveness.rawValue, Cap.onBodyMotion.rawValue, Cap.highRateIMU.rawValue,
                        Cap.secureElement.rawValue, Cap.sameBody.rawValue, Cap.identity.rawValue],
                       [1, 2, 4, 8, 16, 32])
    }
}
