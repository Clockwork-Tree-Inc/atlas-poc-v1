import Foundation

/// Custom profile fields — LinkedIn-style claims + endorsements. Swift parity with
/// `backend/atlas/profile_fields.py` (Python reference of record).
///
/// Any category you want. Each value is a CLAIM you make and sign. Then ANYONE — a person or an org —
/// can ENDORSE it by signing. A value is either an unendorsed claim or a CONFIRMED claim (has ≥1 signed
/// endorsement). Many endorsers per value: 10 people + 3 orgs can confirm your MBBS, 2 your MD. Atlas
/// makes NO trust judgement and has no "trusted" label — the viewer sees WHO endorsed each value (each
/// openable to its signed proof) and decides for themselves.
public enum ProfileFields {

    /// What an endorser signs to confirm a (label, value), e.g. "work:MBBS".
    public static func fieldClaim(_ label: String, _ value: String) -> String { "\(label):\(value)" }

    public enum ProfileError: Error { case foreignField }

    public struct ProfileField {
        public let owner: HybridSign.PublicKey
        public let label: String
        public let values: [String]
        public let endorsements: [Attestation]     // accrue from other keys; NOT part of the owner's signature
        public var selfSig: Data = Data()

        public init(owner: HybridSign.PublicKey, label: String, values: [String],
                    endorsements: [Attestation] = []) {
            self.owner = owner; self.label = label; self.values = values; self.endorsements = endorsements
        }

        public func body() -> Data {
            var joined = Data()
            for (i, v) in values.enumerated() {
                if i > 0 { joined.append(0) }
                joined.append(Data(v.utf8))
            }
            return Primitives.H(Data("atlas/profile-field/v1".utf8), owner.encode(), Data(label.utf8), joined)
        }
    }

    /// Who confirmed a value, with the signed proof so a UI can open it and re-verify it.
    public struct Endorser {
        public let name: String
        public let key: HybridSign.PublicKey
        public let proof: Attestation
    }

    /// One value of a field and everyone who endorsed it. `confirmed` is just "has ≥1 endorser".
    public struct ValueEntry {
        public let value: String
        public let endorsers: [Endorser]
        public var confirmed: Bool { !endorsers.isEmpty }
    }

    public struct FieldView {
        public let label: String
        public let ownerSigned: Bool
        public let entries: [ValueEntry]
    }

    /// Create + self-sign a field (your claim).
    public static func makeField(_ owner: HybridSign.Keypair, label: String, values: [String],
                                 endorsements: [Attestation] = []) throws -> ProfileField {
        var f = ProfileField(owner: owner.publicKey, label: label, values: values, endorsements: endorsements)
        f.selfSig = try HybridSign.sign(owner, f.body())
        return f
    }

    /// Anyone signs an endorsement of `subject`'s (label, value), bound to the subject and exact claim.
    public static func endorse(_ endorser: HybridSign.Keypair, subject: HybridSign.PublicKey,
                               label: String, value: String, endorserName: String = "") throws -> Attestation {
        try issueAttestation(authority: endorser, authorityName: endorserName, subject: subject.encode(),
                             claim: fieldClaim(label, value))
    }

    /// Attach endorsements gathered from others (does not touch the owner's self-signature).
    public static func addEndorsements(_ f: ProfileField, _ endorsements: [Attestation]) -> ProfileField {
        var g = ProfileField(owner: f.owner, label: f.label, values: f.values,
                             endorsements: f.endorsements + endorsements)
        g.selfSig = f.selfSig
        return g
    }

    public static func verifySelf(_ f: ProfileField) -> Bool {
        HybridSign.verify(f.owner, f.body(), f.selfSig)
    }

    /// Render the field: each value with everyone who validly endorsed THAT value. No trust judgement.
    public static func view(_ f: ProfileField) -> FieldView {
        let ownerKey = f.owner.encode()
        let entries = f.values.map { value -> ValueEntry in
            let want = fieldClaim(f.label, value)
            let endorsers = f.endorsements
                .filter { verifyAttestation($0) && $0.subject == ownerKey && $0.claim == want }
                .map { Endorser(name: $0.authorityName, key: $0.authority, proof: $0) }
            return ValueEntry(value: value, endorsers: endorsers)
        }
        return FieldView(label: f.label, ownerSigned: verifySelf(f), entries: entries)
    }

    /// A fully self-defined profile: an ordered set of custom fields owned by one persona key.
    public struct CustomProfile {
        public let owner: HybridSign.PublicKey
        public private(set) var fields: [ProfileField]
        public init(owner: HybridSign.PublicKey, fields: [ProfileField] = []) {
            self.owner = owner; self.fields = fields
        }
        public func withField(_ f: ProfileField) throws -> CustomProfile {
            guard f.owner.encode() == owner.encode() else { throw ProfileError.foreignField }
            return CustomProfile(owner: owner, fields: fields + [f])
        }
    }
}
