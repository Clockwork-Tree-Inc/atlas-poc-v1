import Foundation

/// Credential issuers — the accountable real-world authorities that MINT and REVOKE the attestations
/// the gates consume (Real-ID verifier, company registry, sector body). Parity with
/// `backend/atlas/issuers.py`. Verification-not-authority: an issuer's power is only that some
/// consumer trusts its KEY; Atlas anoints no root. Revocation is a published set of revoked ids.
public enum Issuers {

    static let credentialIDLabel = Data("atlas/credential-id".utf8)

    public static func categoryClaim(_ sector: String) -> String { "category:\(sector)" }

    public static func credentialID(_ att: Attestation) -> Data {
        Primitives.H(credentialIDLabel, att.body())
    }

    /// An accountable authority that issues + revokes attestations. Its trust is its KEY, nothing more.
    public final class Issuer {
        private let kp: HybridSign.Keypair
        public let name: String
        private var revoked: Set<Data> = []

        public init(_ kp: HybridSign.Keypair, name: String) { self.kp = kp; self.name = name }

        public var publicKey: HybridSign.PublicKey { kp.publicKey }

        public func issue(subject: Data, claim: String, epoch: Int = 0) throws -> Attestation {
            try issueAttestation(authority: kp, authorityName: name, subject: subject, claim: claim, epoch: epoch)
        }

        public func issueRealID(subject: Data, epoch: Int = 0) throws -> Attestation {
            try issue(subject: subject, claim: SupplyGate.realIDClaim, epoch: epoch)
        }
        public func issueRegistration(subject: Data, epoch: Int = 0) throws -> Attestation {
            try issue(subject: subject, claim: SupplyGate.registrationClaim, epoch: epoch)
        }
        public func issueCategory(subject: Data, sector: String, epoch: Int = 0) throws -> Attestation {
            try issue(subject: subject, claim: Issuers.categoryClaim(sector), epoch: epoch)
        }

        public func revoke(_ att: Attestation) { revoked.insert(Issuers.credentialID(att)) }
        public func isRevoked(_ att: Attestation) -> Bool { revoked.contains(Issuers.credentialID(att)) }
        public var revocationSet: Set<Data> { revoked }
    }

    /// A credential counts iff its signature verifies, its issuer key is trusted, and it is not revoked.
    public static func validCredential(_ att: Attestation, trustedIssuerKeys: Set<Data>,
                                       revoked: Set<Data> = []) -> Bool {
        verifyAttestation(att)
            && trustedIssuerKeys.contains(att.authority.encode())
            && !revoked.contains(credentialID(att))
    }
}
