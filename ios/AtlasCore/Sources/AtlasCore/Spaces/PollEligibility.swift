import Foundation

/// Eligibility for polls/reviews — "a verified member of the right space at the right role/category
/// can respond anonymously." Byte-for-byte parity with `backend/atlas/spaces/poll_eligibility.py`
/// (Python is reference-of-record). Closes the eligibility SEAM `Polls` leaves open (it dedups
/// nullifiers + checks signatures, but never verifies the voter is actually an eligible member).
///
/// A scoped eligible SET is a Merkle accumulator of member commitments for a (space, scope), where
/// scope is the role/category label (""=whole space; "governor", "healthcare", …), snapshotted at
/// poll open as `memberSetRoot` + `eligibleSize` (the sample size shown per poll — no minimum). A
/// member commitment `H(root, space, scope)` proves "verified member of this scoped set" without
/// revealing which member; the vote carries a PER-POLL nullifier `H(root, pollID)` — one response
/// per member per poll, unlinkable across polls.
///
/// Honest residual (same seam `Polls` names, made concrete): the commitment + Merkle path let a
/// tallier CONFIRM eligibility but the commitment is stable per-(space,scope), so a curious tallier
/// could link a member's ballots across polls and a published proof could be replayed with another
/// nullifier. Production swaps (commitment, path) for a ZK membership proof revealing only the
/// per-poll nullifier and binding nullifier↔membership. This is the verifiable, testable floor.
public enum PollEligibility {

    static let memberLabel = Data("atlas/space-member".utf8)
    static let pollNullifierLabel = Data("atlas/poll-nullifier".utf8)
    static let memberBindLabel = Data("atlas/space-member-bind".utf8)

    static func lp(_ d: Data) -> Data {
        var n = UInt32(d.count).bigEndian
        return withUnsafeBytes(of: &n) { Data($0) } + d
    }

    public static func memberCommitment(root: Data, spaceID: Data, scope: Data = Data()) -> Data {
        Primitives.H(memberLabel, lp(root), lp(spaceID), lp(scope))
    }

    public static func pollNullifier(root: Data, pollID: Data) -> Data {
        Primitives.H(pollNullifierLabel, lp(root), lp(pollID))
    }

    /// A Merkle accumulator of member commitments for one (space, scope). Enroll from verified
    /// members (the personhood check is the caller's gate). Snapshot `rootDigest` + `size` at open.
    public final class EligibleSet {
        public let spaceID: Data
        public let scope: Data
        private var commitments: [Data] = []

        public init(spaceID: Data, scope: Data = Data()) {
            self.spaceID = spaceID; self.scope = scope
        }

        public func enroll(root: Data) {
            let c = memberCommitment(root: root, spaceID: spaceID, scope: scope)
            if !commitments.contains(c) { commitments.append(c) }
        }

        public var rootDigest: Data { Merkle.root(commitments) }
        public var size: Int { commitments.count }

        /// Insert a pre-computed member commitment (used by the SpacePolicy bridge).
        public func addCommitment(_ commitment: Data) {
            if !commitments.contains(commitment) { commitments.append(commitment) }
        }

        public func membershipProof(root: Data) throws -> [Merkle.ProofStep] {
            let c = memberCommitment(root: root, spaceID: spaceID, scope: scope)
            guard let idx = commitments.firstIndex(of: c) else { throw EligibilityError.notAMember }
            return Merkle.inclusionProof(commitments, index: idx)
        }
    }

    public enum EligibilityError: Error, Equatable { case notAMember }

    public static func verifyMembership(commitment: Data, proof: [Merkle.ProofStep], setRoot: Data) -> Bool {
        Merkle.verifyInclusion(commitment, proof: proof, root: setRoot)
    }

    /// A `Spaces.PollResponse` paired with the eligibility evidence for its nullifier's owner.
    public struct EligibleBallot {
        public let response: Spaces.PollResponse
        public let commitment: Data
        public let membershipProof: [Merkle.ProofStep]
        public init(response: Spaces.PollResponse, commitment: Data, membershipProof: [Merkle.ProofStep]) {
            self.response = response; self.commitment = commitment; self.membershipProof = membershipProof
        }
    }

    /// A base poll bound to a scoped eligible set, snapshotted at open.
    public struct EligiblePoll {
        public let base: Spaces.Poll
        public let spaceID: Data
        public let scope: Data
        public let memberSetRoot: Data
        public let eligibleSize: Int
    }

    public struct EligiblePollResult {
        public let pollID: Data
        public let counts: [Int]
        public let responses: Int         // distinct eligible members who responded
        public let eligibleSize: Int      // sample size (snapshot of the eligible set)
        public func winner() -> Int {
            guard !counts.isEmpty else { return -1 }
            return counts.indices.max(by: { counts[$0] < counts[$1] })!
        }
    }

    public static func openPoll(_ base: Spaces.Poll, _ eligible: EligibleSet) -> EligiblePoll {
        EligiblePoll(base: base, spaceID: eligible.spaceID, scope: eligible.scope,
                     memberSetRoot: eligible.rootDigest, eligibleSize: eligible.size)
    }

    /// Client-side: derive the per-poll nullifier, cast an ANONYMOUS ballot, package eligibility.
    public static func mintBallot(root: Data, poll: EligiblePoll, choice: Int, epoch: Int,
                                  ephemeralKp: HybridSign.Keypair,
                                  membershipProof: [Merkle.ProofStep]) throws -> EligibleBallot {
        let nul = pollNullifier(root: root, pollID: poll.base.pollID())
        let resp = try Spaces.respondAnonymously(poll.base, choice: choice, nullifier: nul,
                                                epoch: epoch, ephemeralKp: ephemeralKp)
        let c = memberCommitment(root: root, spaceID: poll.spaceID, scope: poll.scope)
        return EligibleBallot(response: resp, commitment: c, membershipProof: membershipProof)
    }

    public static func verifyBallot(_ poll: EligiblePoll, _ ballot: EligibleBallot) -> Bool {
        Spaces.verifyResponse(poll.base, ballot.response)
            && verifyMembership(commitment: ballot.commitment, proof: ballot.membershipProof,
                                setRoot: poll.memberSetRoot)
    }

    /// Eligibility-checked tally: keep only ballots from members of the snapshotted set, dedup by the
    /// per-poll nullifier (last valid response wins), and report the sample size alongside responses.
    public static func tally(_ poll: EligiblePoll, _ ballots: [EligibleBallot]) -> EligiblePollResult {
        let eligible = ballots.filter { verifyBallot(poll, $0) }.map { $0.response }
        let result = Spaces.tally(poll.base, eligible)
        return EligiblePollResult(pollID: result.pollID, counts: result.counts,
                                  responses: result.total, eligibleSize: poll.eligibleSize)
    }

    // MARK: - SpacePolicy bridge
    //
    // A SpacePolicy knows members by public key; a poll's anonymity needs a hiding per-space
    // commitment from the member's secret root. The member self-binds: signs their anonymous
    // commitment with their authorized key. The bridge admits a commitment iff its signer is a
    // current member at the required role. (Binding reveals pubkey↔commitment to the set builder at
    // enroll time; production blinds it — same seam as the ballot layer.)

    static func bindBody(spaceID: Data, scope: Data, commitment: Data) -> Data {
        Primitives.H(memberBindLabel, lp(spaceID), lp(scope), lp(commitment))
    }

    public struct MembershipBinding {
        public let pub: HybridSign.PublicKey
        public let commitment: Data
        public let sig: Data
        public init(pub: HybridSign.PublicKey, commitment: Data, sig: Data) {
            self.pub = pub; self.commitment = commitment; self.sig = sig
        }
    }

    /// Member-side: compute your per-(space, scope) commitment and sign it with your authorized key.
    public static func bindMembership(root: Data, spaceID: Data, kp: HybridSign.Keypair,
                                      scope: Data = Data()) throws -> MembershipBinding {
        let c = memberCommitment(root: root, spaceID: spaceID, scope: scope)
        let sig = try HybridSign.sign(kp, bindBody(spaceID: spaceID, scope: scope, commitment: c))
        return MembershipBinding(pub: kp.publicKey, commitment: c, sig: sig)
    }

    public static func verifyBinding(_ b: MembershipBinding, spaceID: Data, scope: Data) -> Bool {
        HybridSign.verify(b.pub, bindBody(spaceID: spaceID, scope: scope, commitment: b.commitment), b.sig)
    }

    /// Build a poll's eligible set from a space's members: admit a binding's commitment iff its signer
    /// is a current member at >= `minimumRole` and the binding verifies.
    public static func eligibleSet(from policy: SpaceGovernance.SpacePolicy,
                                   minimumRole: SpaceGovernance.Role, scope: Data,
                                   bindings: [MembershipBinding]) -> EligibleSet {
        let s = EligibleSet(spaceID: policy.spaceID, scope: scope)
        let allowed = Set(policy.membersAt(minimumRole))
        for b in bindings where allowed.contains(b.pub.encode()) && verifyBinding(b, spaceID: policy.spaceID, scope: scope) {
            s.addCommitment(b.commitment)
        }
        return s
    }
}
