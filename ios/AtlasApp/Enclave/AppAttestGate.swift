import Foundation
import DeviceCheck
import CryptoKit

/// Attestation gate: device + firmware via App Attest / DeviceCheck (§6).
///
/// Proves the app is a genuine, unmodified build on genuine Apple hardware — the
/// precondition for enrolment and for every recovery path (§7.3 "attested HW+FW").
/// Honest limit (§1.1 Tier 3): this proves the protocol on a stock device; it
/// does not prove sovereignty (cannot strip telemetry / run alt-OS).
public final class AppAttestGate {
    public enum AttestError: Error { case unsupported, noKey }
    private let service = DCAppAttestService.shared
    private var keyID: String?

    public init() {}
    public var isSupported: Bool { service.isSupported }

    /// One-time per install: generate an App Attest key and attest it to Apple.
    /// `challenge` should come from your verifier (here, the Mac node).
    public func attestKey(challenge: Data) async throws -> (keyID: String, attestation: Data) {
        guard service.isSupported else { throw AttestError.unsupported }
        let keyID = try await service.generateKey()
        self.keyID = keyID
        let hash = Data(SHA256.hash(data: challenge))
        let attestation = try await service.attestKey(keyID, clientDataHash: hash)
        return (keyID, attestation)
    }

    /// Per-request assertion proving the request came from the attested app.
    public func assert(requestData: Data) async throws -> Data {
        guard let keyID else { throw AttestError.noKey }
        let hash = Data(SHA256.hash(data: requestData))
        return try await service.generateAssertion(keyID, clientDataHash: hash)
    }
}
