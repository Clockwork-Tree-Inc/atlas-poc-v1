import Foundation

/// Per-scope (space) pseudonyms + personhood (TRUST_LAYER.md #13). Mirrors
/// `backend/atlas/realid/space_pseudonym.py`.
///
/// `nym = PRF(root, space)` is STABLE within a space, UNLINKABLE across, NON-REVEALING of the
/// root. Sybil-resistance has two layers: (a) deterministic derivation ⇒ one root = one identity
/// per space, and (b) `SpaceRegistry.register` REQUIRES a `PersonhoodAuthority` membership proof
/// that the root is a verified unique human — so fake/arbitrary roots admit nothing. Hashing is
/// length-prefixed so adjacent variable-length fields cannot collide.
public enum SpacePseudonym {

    public enum SpaceError: Error, Equatable { case sybil, personhood }

    static let nymLabel = Data("atlas/space-nym".utf8)
    static let nullifierLabel = Data("atlas/space-nullifier".utf8)
    static let personhoodLabel = Data("atlas/personhood-commit".utf8)

    static func lp(_ d: Data) -> Data {
        var n = UInt32(d.count).bigEndian
        return withUnsafeBytes(of: &n) { Data($0) } + d
    }

    public static func spaceNym(root: Data, spaceID: Data) -> Data {
        Primitives.H(nymLabel, lp(root), lp(spaceID))
    }
    public static func spaceNullifier(root: Data, spaceID: Data) -> Data {
        Primitives.H(nullifierLabel, lp(root), lp(spaceID))
    }

    /// A commitment to a person's root, enrolled once in the verified-humans set.
    public static func personhoodCommitment(root: Data) -> Data {
        Primitives.H(personhoodLabel, lp(root))
    }

    /// The verified-humans set — a Merkle accumulator of personhood commitments. `rootDigest` is
    /// the trusted published commitment; a membership proof shows a root is in it.
    public final class PersonhoodAuthority {
        private var commitments: [Data] = []
        public init() {}
        public func enroll(root: Data) {
            let c = personhoodCommitment(root: root)
            if !commitments.contains(c) { commitments.append(c) }
        }
        public var rootDigest: Data { Merkle.root(commitments) }
        public func membershipProof(root: Data) throws -> [Merkle.ProofStep] {
            let c = personhoodCommitment(root: root)
            guard let idx = commitments.firstIndex(of: c) else { throw SpaceError.personhood }
            return Merkle.inclusionProof(commitments, index: idx)
        }
    }

    public static func verifyPersonhood(root: Data, proof: [Merkle.ProofStep], authorityRoot: Data) -> Bool {
        Merkle.verifyInclusion(personhoodCommitment(root: root), proof: proof, root: authorityRoot)
    }

    public struct SpaceMembership: Equatable {
        public let spaceID: Data
        public let nym: Data
        public let nullifier: Data
    }

    /// A derivation helper (not a gate) — the gate is `SpaceRegistry.register`.
    public static func joinSpace(root: Data, spaceID: Data) -> SpaceMembership {
        SpaceMembership(spaceID: spaceID,
                        nym: spaceNym(root: root, spaceID: spaceID),
                        nullifier: spaceNullifier(root: root, spaceID: spaceID))
    }

    /// Real sybil-resistant membership set: registration REQUIRES a personhood proof, and the
    /// nym/nullifier are DERIVED from the verified root (never accepted from the caller).
    public final class SpaceRegistry {
        public let spaceID: Data
        public let authorityRoot: Data
        private var nymOf: [Data: Data] = [:]   // nullifier -> nym
        public init(spaceID: Data, authorityRoot: Data) {
            self.spaceID = spaceID; self.authorityRoot = authorityRoot
        }

        @discardableResult
        public func register(root: Data, membershipProof: [Merkle.ProofStep]) throws -> Data {
            guard verifyPersonhood(root: root, proof: membershipProof, authorityRoot: authorityRoot) else {
                throw SpaceError.personhood
            }
            let nullifier = spaceNullifier(root: root, spaceID: spaceID)
            let nym = spaceNym(root: root, spaceID: spaceID)
            if let seen = nymOf[nullifier] {
                guard seen == nym else { throw SpaceError.sybil }
                return nym                          // idempotent re-join
            }
            nymOf[nullifier] = nym
            return nym
        }

        public func isMember(_ nym: Data) -> Bool { nymOf.values.contains(nym) }
        public var size: Int { nymOf.count }
    }
}
