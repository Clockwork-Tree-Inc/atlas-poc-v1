import XCTest
@testable import AtlasCore

final class PollEligibilityTests: XCTestCase {
    private func kp(_ n: UInt8) -> HybridSign.Keypair { try! HybridSign.keypair(fromSeed: Data(repeating: n, count: 32)) }
    private func root(_ n: UInt8) -> Data { Data(repeating: n, count: 32) }
    private let space = Data("space:acme".utf8)
    private let opts = [Data("yes".utf8), Data("no".utf8), Data("maybe".utf8)]

    private func basePoll(_ epoch: Int = 1, q: String = "ship it?") throws -> Spaces.Poll {
        try Spaces.createPoll(kp(1), question: Data(q.utf8), options: opts, tier: .anonymous, epoch: epoch)
    }
    private func setWith(_ members: [Data], scope: Data = Data()) -> PollEligibility.EligibleSet {
        let s = PollEligibility.EligibleSet(spaceID: space, scope: scope)
        members.forEach { s.enroll(root: $0) }
        return s
    }

    func testEligibleMemberCountsAndSampleSize() throws {
        let members = [root(10), root(11), root(12)]
        let s = setWith(members)
        let poll = PollEligibility.openPoll(try basePoll(), s)
        XCTAssertEqual(poll.eligibleSize, 3)

        var ballots: [PollEligibility.EligibleBallot] = []
        for (i, m) in members.enumerated() {
            ballots.append(try PollEligibility.mintBallot(root: m, poll: poll, choice: i % 3, epoch: 1,
                                                          ephemeralKp: kp(UInt8(100 + i)),
                                                          membershipProof: try s.membershipProof(root: m)))
        }
        let res = PollEligibility.tally(poll, ballots)
        XCTAssertEqual(res.responses, 3)
        XCTAssertEqual(res.eligibleSize, 3)
        XCTAssertEqual(res.counts.reduce(0, +), 3)
    }

    func testNonMemberExcluded() throws {
        let s = setWith([root(10), root(11)])
        let poll = PollEligibility.openPoll(try basePoll(), s)
        let outsider = root(99)
        let nul = PollEligibility.pollNullifier(root: outsider, pollID: poll.base.pollID())
        let resp = try Spaces.respondAnonymously(poll.base, choice: 0, nullifier: nul, epoch: 1, ephemeralKp: kp(199))
        let forged = PollEligibility.EligibleBallot(
            response: resp,
            commitment: PollEligibility.memberCommitment(root: outsider, spaceID: space),
            membershipProof: [])
        XCTAssertFalse(PollEligibility.verifyBallot(poll, forged))
        XCTAssertEqual(PollEligibility.tally(poll, [forged]).responses, 0)
    }

    func testOneVoteChangeFlips() throws {
        let m = root(10)
        let s = setWith([m, root(11)])
        let poll = PollEligibility.openPoll(try basePoll(), s)
        let proof = try s.membershipProof(root: m)
        let b1 = try PollEligibility.mintBallot(root: m, poll: poll, choice: 0, epoch: 1, ephemeralKp: kp(100), membershipProof: proof)
        let b2 = try PollEligibility.mintBallot(root: m, poll: poll, choice: 1, epoch: 2, ephemeralKp: kp(101), membershipProof: proof)
        let res = PollEligibility.tally(poll, [b1, b2])
        XCTAssertEqual(res.responses, 1)
        XCTAssertEqual(res.counts[1], 1)
        XCTAssertEqual(res.counts[0], 0)
    }

    func testNullifiersUnlinkableAcrossPolls() throws {
        let m = root(10)
        let s = setWith([m, root(11)])
        let p1 = PollEligibility.openPoll(try basePoll(1, q: "q1"), s)
        let p2 = PollEligibility.openPoll(try basePoll(2, q: "q2"), s)
        let n1 = PollEligibility.pollNullifier(root: m, pollID: p1.base.pollID())
        let n2 = PollEligibility.pollNullifier(root: m, pollID: p2.base.pollID())
        XCTAssertNotEqual(n1, n2)
    }

    func testScopeGatesByRole() throws {
        let gov = root(10), worker = root(11)
        let governors = setWith([gov], scope: Data("governor".utf8))
        let poll = PollEligibility.openPoll(try basePoll(), governors)
        XCTAssertEqual(poll.eligibleSize, 1)
        let ok = try PollEligibility.mintBallot(root: gov, poll: poll, choice: 0, epoch: 1,
                                                ephemeralKp: kp(100), membershipProof: try governors.membershipProof(root: gov))
        XCTAssertTrue(PollEligibility.verifyBallot(poll, ok))
        XCTAssertThrowsError(try governors.membershipProof(root: worker))
    }

    func testWrongScopeCommitmentFails() throws {
        let m = root(10)
        let s = setWith([m], scope: Data("governor".utf8))
        let poll = PollEligibility.openPoll(try basePoll(), s)
        let proof = try s.membershipProof(root: m)
        let wrong = PollEligibility.memberCommitment(root: m, spaceID: space)   // scope "" vs "governor"
        XCTAssertFalse(PollEligibility.verifyMembership(commitment: wrong, proof: proof, setRoot: poll.memberSetRoot))
    }

    // MARK: - SpacePolicy bridge
    private func policyWith(_ creator: HybridSign.Keypair, _ grants: [(HybridSign.Keypair, SpaceGovernance.Role, Int)]) throws -> SpaceGovernance.SpacePolicy {
        let p = SpaceGovernance.SpacePolicy.genesis(spaceID: space, creator: creator.publicKey)
        for (who, role, ep) in grants {
            let ch = try p.propose("grant", target: who.publicKey, role: role, epoch: ep)
            try p.authorize(ch, approvals: [(creator.publicKey, try HybridSign.sign(creator, ch.body()))])
        }
        return p
    }

    func testEligibleSetFromPolicyAdmitsOnlyAuthorized() throws {
        let creator = kp(1), worker = kp(2), outsider = kp(9)
        let p = try policyWith(creator, [(worker, .contributor, 1)])
        let bc = try PollEligibility.bindMembership(root: root(1), spaceID: p.spaceID, kp: creator)
        let bw = try PollEligibility.bindMembership(root: root(2), spaceID: p.spaceID, kp: worker)
        let bo = try PollEligibility.bindMembership(root: root(9), spaceID: p.spaceID, kp: outsider)
        let s = PollEligibility.eligibleSet(from: p, minimumRole: .contributor, scope: Data(), bindings: [bc, bw, bo])
        XCTAssertEqual(s.size, 2)   // creator(governor) + worker; outsider excluded
        let poll = PollEligibility.openPoll(try basePoll(), s)
        let ballot = try PollEligibility.mintBallot(root: root(2), poll: poll, choice: 1, epoch: 1,
                                                    ephemeralKp: kp(102), membershipProof: try s.membershipProof(root: root(2)))
        XCTAssertTrue(PollEligibility.verifyBallot(poll, ballot))
        XCTAssertEqual(PollEligibility.tally(poll, [ballot]).eligibleSize, 2)
    }

    func testBridgeRespectsRoleScoping() throws {
        let creator = kp(1), worker = kp(2)
        let p = try policyWith(creator, [(worker, .contributor, 1)])
        let bc = try PollEligibility.bindMembership(root: root(1), spaceID: p.spaceID, kp: creator)
        let bw = try PollEligibility.bindMembership(root: root(2), spaceID: p.spaceID, kp: worker)
        let govOnly = PollEligibility.eligibleSet(from: p, minimumRole: .governor, scope: Data(), bindings: [bc, bw])
        XCTAssertEqual(govOnly.size, 1)
    }

    func testForgedBindingRejected() throws {
        let creator = kp(1), worker = kp(2)
        let p = try policyWith(creator, [(worker, .contributor, 1)])
        let realWorker = try PollEligibility.bindMembership(root: root(2), spaceID: p.spaceID, kp: worker)
        let bad = PollEligibility.MembershipBinding(pub: worker.publicKey,
            commitment: PollEligibility.memberCommitment(root: root(1), spaceID: p.spaceID),
            sig: realWorker.sig)
        XCTAssertFalse(PollEligibility.verifyBinding(bad, spaceID: p.spaceID, scope: Data()))
        let s = PollEligibility.eligibleSet(from: p, minimumRole: .contributor, scope: Data(), bindings: [bad])
        XCTAssertEqual(s.size, 0)
    }

}
