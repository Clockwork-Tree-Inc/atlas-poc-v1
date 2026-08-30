import Foundation

/// Participant & profile — everyone and everything is ONE participant class. Swift parity with
/// `backend/atlas/participant.py` (Python reference of record).
///
/// A participant is a typed entity (individual / nonprofit / for-profit) operating as a persona
/// handle, with an OPT-IN public profile on the ANONYMOUS -> PUBLIC -> VERIFIED spectrum.
/// Credential authorities are NOT privileged: any participant can issue a signed Attestation about
/// a subject; VERIFICATION-NOT-AUTHORITY means trust binds to the authority KEY the consumer
/// chooses — never a spoofable display name. Atlas anoints no root.

public enum EntityClass: String, Codable, CaseIterable, Sendable {
    // Three top-level kinds: individual (verified human), organization (nonprofit/for-profit — a
    // registered collective legal entity), agent (an AI/autonomous actor that is never a root — see
    // AgentDelegation). Parity with backend/atlas/marketplace.py.
    case individual, nonprofit, forProfit = "for_profit", agent

    /// Organizations = the registered collective-entity classes (fiscal status is the sub-type).
    public var isOrganization: Bool { self == .nonprofit || self == .forProfit }
    /// Only a human or an organization can ROOT authority for an agent — never another agent.
    public var canBePrincipal: Bool { self != .agent }
}

public enum ProfileVisibility: String, Codable, Sendable { case anonymous, publicProfile = "public" }

public enum ParticipantError: Error { case wrongSubject, badAttestation, needsDisplayName }

public struct Attestation {
    public let authorityName: String          // display label ONLY — trust binds to the key
    public let authority: HybridSign.PublicKey
    public let subject: Data                  // subject persona handle
    public let claim: String
    public let epoch: Int
    public var sig: Data = Data()

    public func body() -> Data {
        Primitives.H(Data("atlas/attestation/v1".utf8), Data(authorityName.utf8), subject,
                     Data(claim.utf8), Data(String(epoch).utf8))
    }
}

public func issueAttestation(authority: HybridSign.Keypair, authorityName: String, subject: Data,
                             claim: String, epoch: Int = 0) throws -> Attestation {
    var a = Attestation(authorityName: authorityName, authority: authority.publicKey,
                        subject: subject, claim: claim, epoch: epoch)
    a.sig = try HybridSign.sign(authority, a.body())
    return a
}

public func verifyAttestation(_ a: Attestation) -> Bool {
    HybridSign.verify(a.authority, a.body(), a.sig)
}

/// A participant's self-service profile: anonymous by default; opt into public; "verified" is
/// DERIVED from holding valid authority attestations.
public final class ParticipantProfile {
    public let handle: Data
    public let entityClass: EntityClass
    public let publicKey: HybridSign.PublicKey
    public private(set) var displayName = ""
    public private(set) var bio = ""
    public private(set) var links: [String] = []
    public private(set) var visibility = ProfileVisibility.anonymous
    public private(set) var attestations: [Attestation] = []

    public init(handle: Data, publicKey: HybridSign.PublicKey, entityClass: EntityClass) {
        self.handle = handle; self.publicKey = publicKey; self.entityClass = entityClass
    }

    public func goPublic(displayName: String, bio: String = "", links: [String] = []) throws {
        guard !displayName.isEmpty else { throw ParticipantError.needsDisplayName }
        visibility = .publicProfile
        self.displayName = displayName; self.bio = bio; self.links = links
    }

    public func goAnonymous() {
        visibility = .anonymous; displayName = ""; bio = ""; links = []
    }

    /// Accept an attestation ABOUT this participant — forged or misdirected ones are rejected.
    public func hold(_ a: Attestation) throws {
        guard a.subject == handle else { throw ParticipantError.wrongSubject }
        guard verifyAttestation(a) else { throw ParticipantError.badAttestation }
        attestations.append(a)
    }

    /// Display: the authority NAMES that validly attest this participant (labels, not trust).
    public func verifiedBy() -> [String] {
        attestations.filter { $0.subject == handle && verifyAttestation($0) }.map { $0.authorityName }
    }

    public var isVerified: Bool { visibility == .publicProfile && !verifiedBy().isEmpty }
}

/// A CONSUMER's check: a valid attestation for `claim` from an authority KEY the consumer trusts.
public func presents(_ profile: ParticipantProfile, claim: String,
                     trustedAuthorityKeys: Set<Data>) -> Bool {
    profile.attestations.contains { a in
        a.subject == profile.handle && a.claim == claim && verifyAttestation(a)
            && trustedAuthorityKeys.contains(a.authority.encode())
    }
}
