import Foundation

/// Supply-side Real-ID gate — the regulated boundary of the economy. Parity with
/// `backend/atlas/economy/supply_gate.py` (Python is reference-of-record).
///
/// DEMAND (buy / browse / consume) is anonymous — no credential. SUPPLY (sell / list / earn /
/// provide / own an org / receive payment) requires a `real-id` attestation from a trusted verifier
/// key; an ORGANIZATION also needs a `registered` attestation from a trusted registry. Real-ID ≠
/// doxxed (checks HOLDING the credential, not going public). An AGENT is never a direct supply actor
/// — it acts via a delegation whose root principal is gated instead (see AgentDelegation).
public enum SupplyGate {

    public static let realIDClaim = "real-id"
    public static let registrationClaim = "registered"

    public static let demandActions: Set<String> = ["buy", "browse", "consume", "read_review"]
    public static let supplyActions: Set<String> = ["sell", "list", "earn", "provide", "own_org", "receive_payment"]

    public enum SupplyGateError: Error, Equatable { case unknownAction }

    public static func hasRealID(_ profile: ParticipantProfile, trustedVerifierKeys: Set<Data>) -> Bool {
        presents(profile, claim: realIDClaim, trustedAuthorityKeys: trustedVerifierKeys)
    }

    public static func hasRegistration(_ profile: ParticipantProfile, trustedRegistryKeys: Set<Data>) -> Bool {
        presents(profile, claim: registrationClaim, trustedAuthorityKeys: trustedRegistryKeys)
    }

    public static func isSupply(_ action: String) -> Bool { supplyActions.contains(action) }

    /// May this profile perform `action`? Demand always allowed; supply needs a trusted Real-ID (+
    /// registration for an organization); an agent is never a direct supply actor.
    public static func canPerform(_ profile: ParticipantProfile, action: String,
                                  trustedVerifierKeys: Set<Data> = [],
                                  trustedRegistryKeys: Set<Data> = []) throws -> Bool {
        if demandActions.contains(action) { return true }
        guard supplyActions.contains(action) else { throw SupplyGateError.unknownAction }

        if profile.entityClass == .agent { return false }
        if !hasRealID(profile, trustedVerifierKeys: trustedVerifierKeys) { return false }
        if profile.entityClass.isOrganization
            && !hasRegistration(profile, trustedRegistryKeys: trustedRegistryKeys) { return false }
        return true
    }
}
